package update

import (
	"strings"
	"time"
)

const (
	rolledBackError  = "BOOT_ROLLED_BACK: target slot is bad; the previously running slot is booted, good and primary"
	supersededError  = "SUPERSEDED: a newer complete installation replaced the target slot pair"
	bootUnknownError = "BOOT_RESULT_UNKNOWN: the saved installation cannot be confirmed from the current boot and slot evidence"
)

// Keep the format-1 state vocabulary readable by older Core versions. Unknown
// boot outcomes are final observations, unlike interrupted install requests.
func resolvedBootOutcome(t Task) bool {
	return t.State == Unknown && strings.HasPrefix(t.Error, "BOOT_RESULT_UNKNOWN:")
}

func slotPair(slots []SlotEvidence, target string) (root, boot SlotEvidence, ok bool) {
	count := 0
	for _, slot := range slots {
		if slot.Name != target && slot.Parent != target {
			continue
		}
		count++
		if slot.Name == target && slot.Class == "rootfs" && slot.Parent == "" {
			root = slot
		} else if slot.Parent == target && slot.Class == "boot" {
			boot = slot
		} else {
			return root, boot, false
		}
	}
	return root, boot, count == 2 && root.Name != "" && boot.Name != ""
}

func completeImage(slot SlotEvidence) bool {
	_, err := time.Parse(time.RFC3339, slot.InstalledAt)
	return slot.Status == "ok" && slot.Version != "" && len(slot.ManifestHash) == 64 && len(slot.SHA256) == 64 && slot.InstalledCount > 0 && err == nil
}

func superseded(t Task, s snapshot) bool {
	oldRoot, oldBoot, ok := slotPair(t.Installed, t.TargetSlot)
	if !ok || !completeImage(oldRoot) || !completeImage(oldBoot) || oldRoot.Transaction == "" || oldRoot.Transaction != oldBoot.Transaction || oldRoot.Version != oldBoot.Version || oldRoot.ManifestHash != oldBoot.ManifestHash {
		return false
	}
	root, boot, ok := slotPair(s.Slots, t.TargetSlot)
	if !ok || root.Name != oldRoot.Name || boot.Name != oldBoot.Name || root.Bootname != oldRoot.Bootname || !completeImage(root) || !completeImage(boot) || root.Version != boot.Version || root.ManifestHash != boot.ManifestHash {
		return false
	}
	// RAUC 1.15.2 can omit both transaction fields after service restart. New
	// counters and timestamps on both complete images still prove replacement.
	if root.Transaction != boot.Transaction || root.Transaction != "" && root.Transaction == oldRoot.Transaction {
		return false
	}
	for _, pair := range [][2]SlotEvidence{{oldRoot, root}, {oldBoot, boot}} {
		before, _ := time.Parse(time.RFC3339, pair[0].InstalledAt)
		after, _ := time.Parse(time.RFC3339, pair[1].InstalledAt)
		if pair[1].InstalledCount <= pair[0].InstalledCount || after.Before(before) {
			return false
		}
	}
	return true
}

// BootSlot and state must agree on one rootfs. A stale or contradictory state
// field alone cannot establish that a different slot actually booted.
func actualRoot(slots []SlotEvidence, bootSlot string) (SlotEvidence, bool) {
	var root SlotEvidence
	for _, slot := range slots {
		if slot.Class != "rootfs" || slot.Parent != "" {
			continue
		}
		matches := bootSlot != "" && (slot.Name == bootSlot || slot.Bootname == bootSlot || slot.Device == bootSlot)
		if matches != (slot.State == "booted") {
			return SlotEvidence{}, false
		}
		if matches {
			if root.Name != "" {
				return SlotEvidence{}, false
			}
			root = slot
		}
	}
	return root, root.Name != ""
}

func rolledBack(t Task, s snapshot, running SlotEvidence) bool {
	original, ok := actualRoot(t.Before, t.BootSlot)
	if !ok || original.Name == t.TargetSlot || running.Name != original.Name || running.BootStatus != "good" || s.Primary != running.Name || !sameInstalledEvidence(t, s) {
		return false
	}
	target, _, ok := slotPair(s.Slots, t.TargetSlot)
	return ok && target.BootStatus == "bad"
}

// Reuse an idle snapshot already obtained for a current installation or a new
// boot. Same-boot pending tasks do not themselves enable permanent polling.
func (c *Client) settlePending(s snapshot) error {
	p := c.persistent
	running, bootKnown := actualRoot(s.Slots, s.BootSlot)
	for _, t := range p.tasks {
		if t.State != InstalledPendingReboot {
			continue
		}
		switch {
		case c.canConfirm(t, s):
			t.State, t.Error = BootConfirmed, ""
		case superseded(t, s):
			t.State, t.Error = Failed, supersededError
		case sameInstalledEvidence(t, s) && (bootloaderTask(t) && unchangedOS(t, s) || !bootloaderTask(t) && (t.BootID == p.bootID || bootKnown && running.Name == t.TargetSlot)):
			// An intact installation on the same boot still awaits reboot. A
			// matching target boot still awaits the existing confirmation path.
			continue
		case t.BootID != p.bootID && bootKnown && rolledBack(t, s, running):
			t.State, t.Error = Failed, rolledBackError
		default:
			t.State, t.Error = Unknown, bootUnknownError
		}
		// Keep the saved original BootSlot for rollback attribution until this
		// terminal transition; installation result and evidence remain intact.
		t.BootSlot, t.Primary = s.BootSlot, s.Primary
		if err := c.commit(t); err != nil {
			return err
		}
	}
	return nil
}
