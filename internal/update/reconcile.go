package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

func oldSlot(t Task, name string) SlotEvidence {
	for _, s := range t.Before {
		if s.Name == name {
			return s
		}
	}
	return SlotEvidence{}
}

// Evidence covers the selected rootfs and its boot child. Local transactions
// are supplied to RAUC; external jobs need a new common transaction, version,
// hashes, timestamp and baseline counters. Exit zero is not installation proof.
func installedEvidence(t Task, s snapshot) ([]SlotEvidence, bool) {
	if bootloaderTask(t) {
		return loaderInstalledEvidence(t, s)
	}
	if t.Source == "hawkbit" && len(t.Images) == 0 {
		if cohort, ok := loaderInstalledEvidence(t, s); ok {
			return cohort, true
		}
	}
	if s.Primary != t.TargetSlot {
		return nil, false
	}
	var cohort []SlotEvidence
	for _, slot := range s.Slots {
		if slot.Name == t.TargetSlot || slot.Parent == t.TargetSlot {
			cohort = append(cohort, slot)
		}
	}
	if len(cohort) != 2 {
		return nil, false
	}
	if t.Source == "hawkbit" && !unchangedOutside(t, s, cohort[0].Name, cohort[1].Name) {
		return nil, false
	}
	classes := map[string]bool{}
	transaction, hash, version := "", "", ""
	for _, slot := range cohort {
		if slot.Status != "ok" || len(slot.SHA256) != 64 || len(slot.ManifestHash) != 64 || slot.Transaction == "" || slot.Version == "" {
			return nil, false
		}
		if slot.Class != "rootfs" && slot.Class != "boot" || classes[slot.Class] {
			return nil, false
		}
		classes[slot.Class] = true
		if transaction == "" {
			transaction, hash, version = slot.Transaction, slot.ManifestHash, slot.Version
		}
		if slot.Transaction != transaction || slot.ManifestHash != hash || slot.Version != version {
			return nil, false
		}
		if t.Version != "" && slot.Version != t.Version || t.ManifestHash != "" && slot.ManifestHash != t.ManifestHash {
			return nil, false
		}
		if expected := t.Images[slot.Class]; expected != "" && slot.SHA256 != expected {
			return nil, false
		}
		if t.Source == "local" {
			if slot.Transaction != t.ID {
				return nil, false
			}
		} else {
			before := oldSlot(t, slot.Name)
			stamp, err := time.Parse(time.RFC3339, slot.InstalledAt)
			if err != nil || stamp.Before(t.CreatedAt.Truncate(time.Second)) || slot.Transaction == before.Transaction || slot.InstalledCount <= before.InstalledCount {
				return nil, false
			}
		}
	}
	return cohort, classes["rootfs"] && classes["boot"]
}
func sameInstalledEvidence(t Task, s snapshot) bool {
	if len(t.Installed) != 2 {
		return false
	}
	for _, record := range t.Installed {
		// RAUC 1.15.2 writes installed.transaction to central.raucs but does
		// not restore it when loading status after restart. Only an already
		// verified and persisted installation snapshot may bridge that loss.
		if record.Transaction == "" || record.Version == "" || len(record.ManifestHash) != 64 || len(record.SHA256) != 64 || record.InstalledCount == 0 {
			return false
		}
		if _, err := time.Parse(time.RFC3339, record.InstalledAt); err != nil {
			return false
		}
		found := false
		for _, slot := range s.Slots {
			if slot.Name == record.Name && slot.Status == "ok" && slot.Version == record.Version && slot.ManifestHash == record.ManifestHash && slot.SHA256 == record.SHA256 && slot.InstalledAt == record.InstalledAt && slot.InstalledCount == record.InstalledCount && (slot.Transaction == "" || slot.Transaction == record.Transaction) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func (c *Client) canConfirm(t Task, s snapshot) bool {
	p := c.persistent
	if bootloaderTask(t) {
		return t.BootID != p.bootID && verifiedLoaderTask(t) && unchangedOS(t, s) && sameInstalledEvidence(t, s) && p.bootConfirmed()
	}
	running, bootKnown := actualRoot(s.Slots, s.BootSlot)
	if !bootKnown || running.Name != t.TargetSlot || t.BootID == p.bootID || s.Primary != t.TargetSlot || !sameInstalledEvidence(t, s) {
		return false
	}
	confirmed := false
	for _, slot := range s.Slots {
		if slot.Name == t.TargetSlot && booted(slot, s.BootSlot) && slot.BootStatus == "good" {
			confirmed = true
		}
	}
	if !confirmed || !p.bootConfirmed() {
		return false
	}
	return t.Version != "" && p.runningVersion() == t.Version
}
func currentVersion() string {
	data, err := os.ReadFile("/run/naos/lower/usr/lib/naos/version.json")
	if err != nil || len(data) > 65536 {
		return ""
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	return v.Version
}
func openRCConfirmed() bool {
	_, err := os.Stat("/run/openrc/started/naos-boot-confirm")
	return err == nil
}

// A failed proc read is uncertainty, not proof that a worker has exited.
func processState(i *ExternalIdentity, boot string) (alive, known bool) {
	if i == nil {
		return false, false
	}
	if i.BootID != boot {
		return false, true
	}
	if i.PID <= 0 || i.StartTime == 0 {
		return false, false
	}
	prefix := "/proc/" + strconv.Itoa(i.PID)
	data, err := os.ReadFile(prefix + "/stat")
	if err != nil {
		return false, os.IsNotExist(err)
	}
	end := strings.LastIndex(string(data), ") ")
	if end < 0 {
		return false, false
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 {
		return false, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return false, false
	}
	if start != i.StartTime || fields[0] == "Z" || fields[0] == "X" {
		return false, true
	}
	exe, err := os.Readlink(prefix + "/exe")
	if err != nil {
		return false, os.IsNotExist(err)
	}
	if strings.TrimSuffix(exe, " (deleted)") != i.Exe {
		return false, false
	}
	return true, true
}
func processAlive(i *ExternalIdentity, boot string) bool {
	alive, _ := processState(i, boot)
	return alive
}
func updaterPresent() (found, complete bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, false
	}
	complete = true
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		exe, err := os.Readlink("/proc/" + entry.Name() + "/exe")
		if err != nil {
			if os.IsPermission(err) {
				complete = false
			}
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		if strings.HasSuffix(exe, "/rauc-hawkbit-updater") {
			return true, true
		}
	}
	return false, complete
}
func externalMayRun(t Task, boot string, scan func() (bool, bool)) bool {
	if t.Source != "hawkbit" || t.UpdaterExit != nil || t.BootID != boot {
		return false
	}
	alive, known := processState(t.ExternalIdentity, boot)
	if alive {
		return true
	}
	if known {
		return false
	}
	if t.ExternalIdentity != nil {
		return true
	}
	// A restart before Attach must not lock the device forever. Full process
	// inspection, plus the caller's RAUC-idle check, resolves that launch gap.
	present, complete := scan()
	return present || !complete
}
func (c *Client) reconcile(ctx context.Context, status Status) error {
	p := c.persistent
	if p.saveError != nil {
		if err := c.retryPersistence(); err != nil {
			return err
		}
	}
	if p.active != "" {
		t, ok := c.findTask(p.active)
		if !ok {
			return errors.New("active update task missing")
		}
		t.Progress = status.Progress
		if status.Operation != "idle" {
			t.ObservedInstalling = true
			if t.Source == "local" {
				t.State = Installing
			}
			p.lastProgress = time.Now()
			return c.commit(t)
		}
		snap, err := c.snapshot(ctx)
		if err != nil {
			return err
		}
		if c.result != nil {
			result := *c.result
			t.Result = &result
		}
		alive := externalMayRun(t, p.bootID, p.processScan)
		if t.Result != nil && *t.Result != 0 {
			t.State, t.Error = Failed, status.LastError
			if t.Error == "" {
				t.Error = "RAUC installation failed"
			}
			if err := c.commit(t); err != nil {
				return err
			}
			if !alive {
				c.releaseTask()
			}
			return c.settlePending(snap)
		}
		if evidence, ok := installedEvidence(t, snap); ok {
			t.Installed = evidence
			t.State = InstalledPendingReboot
			if _, _, loader := loaderPair(evidence); loader {
				original, _ := actualRoot(t.Before, t.BootSlot)
				t.TargetSlot, t.TargetBootname = original.Name, original.Bootname
				t.Version, t.ManifestHash = evidence[0].Version, evidence[0].ManifestHash
				t.Images = map[string]string{}
				for _, slot := range evidence {
					t.Images[slot.Class] = slot.SHA256
				}
			}
			t.BootSlot, t.Primary = snap.BootSlot, snap.Primary
			for _, slot := range evidence {
				if slot.Name == t.TargetSlot {
					t.Version, t.ManifestHash = slot.Version, slot.ManifestHash
				}
			}
			if c.canConfirm(t, snap) {
				t.State = BootConfirmed
			}
			if err := c.commit(t); err != nil {
				return err
			}
			if !alive {
				c.releaseTask()
			}
			return c.settlePending(snap)
		}
		if alive {
			// Refresh while a long-running download is alive. Wait may reap the
			// child just before EndExternal can acquire this mutex; give that
			// normal exit-code handoff a bounded window for attached jobs too.
			p.lastProgress = time.Now()
		}
		if alive || t.Source == "hawkbit" && t.UpdaterExit == nil && time.Since(p.lastProgress) < 5*time.Second {
			return c.commit(t)
		}
		if t.Source == "local" && c.result == nil && time.Since(p.lastProgress) < 5*time.Second {
			return c.commit(t)
		}
		if p.external != nil && p.external.ID == t.ID && t.Source == "hawkbit" && t.BootID == p.bootID && t.UpdaterExit != nil && *t.UpdaterExit == 0 && t.Error == "" && t.ActionID == "" && t.Version == "" && !t.ObservedInstalling && t.Result == nil && c.result == nil && len(t.Installed) == 0 && unchangedCheck(t, snap) {
			return c.discardEmpty(t)
		}
		t.State = Unknown
		t.Error = "no attributable completed RAUC installation; the request is never automatically resubmitted"
		if t.UpdaterExit != nil && *t.UpdaterExit != 0 {
			t.State = Failed
			t.Error = "updater process failed without verified installation evidence"
		}
		if err := c.commit(t); err != nil {
			return err
		}
		c.releaseTask()
		return c.settlePending(snap)
	}
	pending := false
	for _, t := range p.tasks {
		if t.State == InstalledPendingReboot && t.BootID != p.bootID {
			pending = true
		}
	}
	if pending && status.Operation == "idle" {
		snap, err := c.snapshot(ctx)
		if err != nil {
			return err
		}
		return c.settlePending(snap)
	}
	return nil
}
