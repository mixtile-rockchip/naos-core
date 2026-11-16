package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pendingJournal = "hawkbit-pending.json"
const emptyCheckError = "EMPTY_CHECK: updater exited successfully and complete RAUC slot evidence is unchanged"

func emptyCheck(t Task) bool {
	return t.State == Unknown && strings.HasPrefix(t.Error, "EMPTY_CHECK:")
}

func (s *taskStore) clearPending() error {
	remove := s.removePending
	if remove == nil {
		remove = os.Remove
	}
	if err := remove(filepath.Join(s.dir, pendingJournal)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Also sync after ENOENT: a prior unlink may have succeeded before its
	// directory sync failed. Retrying must finish the durability boundary.
	return s.syncDir()
}

func (c *Client) restorePending() error {
	p := c.persistent
	records, err := p.store.read(pendingJournal, 1)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		if _, err := os.Lstat(filepath.Join(p.store.dir, pendingJournal)); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return errors.New("pending updater journal must contain exactly one task")
	}
	t := records[0]
	if t.Source != "hawkbit" {
		return errors.New("pending updater journal has an invalid source")
	}
	for _, old := range p.tasks {
		if old.ID == t.ID {
			// Main journal wins after a crash between promotion and unlink.
			if old.Source != "hawkbit" || old.RequestID != t.RequestID || old.Path != t.Path {
				return errors.New("pending updater conflicts with durable task")
			}
			return p.store.clearPending()
		}
		if t.RequestID != "" && old.RequestID == t.RequestID {
			return errors.New("pending updater request conflicts with task history")
		}
	}
	p.external = &t
	if t.State != RunningExternal && t.State != Submitted && t.State != Installing {
		// A terminal sidecar may be left by an interrupted promotion. Its saved
		// evidence is already durable; finish publishing it without re-install.
		return c.commit(t)
	}
	return nil
}

func (c *Client) persistExternal(t Task) error {
	p := c.persistent
	// Retain a failed write's desired value in this Client. The observer retries
	// the sidecar protocol before releasing admission or observing a later job.
	if p.external != nil && p.external.ID == t.ID && !sameTask(*p.external, t) {
		t.UpdatedAt = time.Now().UTC()
	}
	copy := cloneTask(t)
	p.external = &copy
	if err := p.store.saveFile(pendingJournal, []Task{t}, 1); err != nil {
		p.saveError = fmt.Errorf("%w: %v", ErrPersistence, err)
		return p.saveError
	}
	if t.State == RunningExternal || t.State == Submitted || t.State == Installing {
		p.saveError = nil
		return nil
	}
	if err := c.commitHistory(t); err != nil {
		return err
	}
	if err := p.store.clearPending(); err != nil {
		p.saveError = fmt.Errorf("%w: clear pending updater: %v", ErrPersistence, err)
		return p.saveError
	}
	p.external, p.saveError = nil, nil
	return nil
}

func (c *Client) retryPersistence() error {
	p := c.persistent
	if p.external != nil {
		return c.persistExternal(*p.external)
	}
	if err := p.store.save(p.tasks); err != nil {
		p.saveError = fmt.Errorf("%w: %v", ErrPersistence, err)
		return p.saveError
	}
	p.saveError = nil
	return nil
}

func (c *Client) discardEmpty(t Task) error {
	p := c.persistent
	if err := p.store.clearPending(); err != nil {
		p.saveError = fmt.Errorf("%w: clear empty updater: %v", ErrPersistence, err)
		return p.saveError
	}
	t.State, t.Error = Unknown, emptyCheckError
	copy := cloneTask(t)
	p.lastEmpty, p.external, p.saveError = &copy, nil, nil
	c.releaseTask()
	return nil
}

func unchangedCheck(t Task, live snapshot) bool {
	if len(t.Before) != len(live.Slots) || !checkTopology(t.Before) || t.BootSlot != live.BootSlot || t.Primary != live.Primary {
		return false
	}
	beforeRoot, beforeKnown := actualRoot(t.Before, t.BootSlot)
	afterRoot, afterKnown := actualRoot(live.Slots, live.BootSlot)
	if !beforeKnown || !afterKnown || beforeRoot.Name != afterRoot.Name {
		return false
	}
	seen := map[string]bool{}
	for _, before := range t.Before {
		if before.Name == "" || seen[before.Name] || !completeCheckRecord(before) {
			return false
		}
		seen[before.Name] = true
		found := false
		for _, after := range live.Slots {
			if before.Name == after.Name {
				// Exact comparison includes transaction absence. A disappearing
				// transaction after RAUC restart cannot prove an empty check.
				found = before == after
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// A freshly flashed slot has no RAUC installation record. RAUC 1.15.2 creates
// a zeroed RaucSlotStatus for it and omits its status/installation D-Bus keys.
func completeCheckRecord(s SlotEvidence) bool {
	if completeImage(s) {
		return true
	}
	return s.Status == "" && s.Version == "" && s.ManifestHash == "" && s.SHA256 == "" && s.Transaction == "" && s.InstalledAt == "" && s.InstalledCount == 0
}

func checkTopology(slots []SlotEvidence) bool {
	if len(slots) < 4 || len(slots) > 32 {
		return false
	}
	devices, bootnames := map[string]bool{}, map[string]bool{}
	roots, bootloaders := 0, 0
	for _, s := range slots {
		if s.Name == "" || !filepath.IsAbs(s.Device) || s.Device == "/" || devices[s.Device] || (s.State != "booted" && s.State != "active" && s.State != "inactive") {
			return false
		}
		devices[s.Device] = true
		switch s.Class {
		case "rootfs":
			if s.Parent != "" || s.Bootname == "" || bootnames[s.Bootname] || (s.BootStatus != "good" && s.BootStatus != "bad") {
				return false
			}
			bootnames[s.Bootname] = true
			if _, _, ok := slotPair(slots, s.Name); !ok {
				return false
			}
			roots++
		case "boot":
			if s.Parent == "" || s.Bootname != "" || s.BootStatus != "" || s.State == "booted" {
				return false
			}
			found := false
			for _, parent := range slots {
				if parent.Name == s.Parent && parent.Class == "rootfs" {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case "idb", "uboot":
			// Shared bootloader slots are updated separately by RAUC. Keep
			// their records in empty-check evidence, outside the OS slot pairs.
			device := "/dev/naos/uboot"
			if s.Class == "idb" {
				device = "/dev/naos/disk"
			}
			if s.Name != s.Class+".0" || s.Device != device || s.Parent != "" || s.Bootname != "" || s.BootStatus != "" || s.State != "inactive" {
				return false
			}
			bootloaders++
		default:
			return false
		}
	}
	return roots*2+bootloaders == len(slots)
}
