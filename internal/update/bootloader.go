package update

import "time"

func checksum(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func systemImages(images map[string]string) bool {
	return len(images) == 2 && checksum(images["rootfs"]) && checksum(images["boot"])
}

func loaderImages(images map[string]string) bool {
	return len(images) == 2 && checksum(images["uboot"]) && checksum(images["idb"])
}

// The existing image map identifies the update kind without changing the
// format-1 journal or making older journals unreadable.
func bootloaderTask(t Task) bool { return loaderImages(t.Images) }

func loaderPair(slots []SlotEvidence) (uboot, idb SlotEvidence, ok bool) {
	count := 0
	for _, slot := range slots {
		if slot.Class != "uboot" && slot.Class != "idb" {
			continue
		}
		count++
		device := "/dev/naos/uboot"
		if slot.Class == "idb" {
			device = "/dev/naos/disk"
		}
		if slot.Name != slot.Class+".0" || slot.Device != device || slot.Parent != "" || slot.Bootname != "" || slot.BootStatus != "" || slot.State != "inactive" {
			return uboot, idb, false
		}
		if slot.Class == "uboot" {
			if uboot.Name != "" {
				return uboot, idb, false
			}
			uboot = slot
		} else {
			if idb.Name != "" {
				return uboot, idb, false
			}
			idb = slot
		}
	}
	return uboot, idb, count == 2 && uboot.Name != "" && idb.Name != ""
}

// Shared bootloader updates leave all OS slot records and the running/primary
// selection intact. A missing transaction after a RAUC restart is tolerated;
// counters, timestamps, identities and image hashes must still match.
func unchangedOutside(t Task, live snapshot, first, second string) bool {
	if len(t.Before) != len(live.Slots) {
		return false
	}
	for _, before := range t.Before {
		if before.Name == first || before.Name == second {
			continue
		}
		found := false
		for _, after := range live.Slots {
			if after.Name == before.Name {
				if after.Transaction == "" {
					before.Transaction = ""
				}
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

func unchangedOS(t Task, live snapshot) bool {
	before, known := actualRoot(t.Before, t.BootSlot)
	running, liveKnown := actualRoot(live.Slots, live.BootSlot)
	if !known || !liveKnown || before.Name != running.Name || running.BootStatus != "good" || t.Primary != before.Name || live.Primary != before.Name || !checkTopology(t.Before) || !checkTopology(live.Slots) {
		return false
	}
	uboot, idb, ok := loaderPair(live.Slots)
	return ok && unchangedOutside(t, live, uboot.Name, idb.Name)
}

func loaderInstalledEvidence(t Task, live snapshot) ([]SlotEvidence, bool) {
	if !unchangedOS(t, live) {
		return nil, false
	}
	uboot, idb, ok := loaderPair(live.Slots)
	if !ok {
		return nil, false
	}
	if _, _, ok := loaderPair(t.Before); !ok {
		return nil, false
	}
	cohort := []SlotEvidence{uboot, idb}
	for _, slot := range cohort {
		before := oldSlot(t, slot.Name)
		stamp, err := time.Parse(time.RFC3339, slot.InstalledAt)
		if !completeImage(slot) || !checksum(slot.SHA256) || !checksum(slot.ManifestHash) || slot.Transaction == "" || slot.Transaction != uboot.Transaction || slot.Version != uboot.Version || slot.ManifestHash != uboot.ManifestHash || err != nil || stamp.Before(t.CreatedAt.Truncate(time.Second)) || slot.InstalledCount <= before.InstalledCount || slot.Transaction == before.Transaction {
			return nil, false
		}
		if t.Version != "" && slot.Version != t.Version || t.ManifestHash != "" && slot.ManifestHash != t.ManifestHash {
			return nil, false
		}
		if expected := t.Images[slot.Class]; expected != "" && slot.SHA256 != expected {
			return nil, false
		}
		if t.Source == "local" && slot.Transaction != t.ID {
			return nil, false
		}
	}
	return cohort, true
}

func verifiedLoaderTask(t Task) bool {
	uboot, idb, ok := loaderPair(t.Installed)
	if !ok || !completeImage(uboot) || !completeImage(idb) || uboot.Transaction == "" || uboot.Transaction != idb.Transaction || uboot.Version != idb.Version || uboot.ManifestHash != idb.ManifestHash || t.Version != uboot.Version || t.ManifestHash != uboot.ManifestHash || !loaderImages(t.Images) || t.Images["uboot"] != uboot.SHA256 || t.Images["idb"] != idb.SHA256 {
		return false
	}
	original, known := actualRoot(t.Before, t.BootSlot)
	return known && original.Name == t.TargetSlot && original.Bootname == t.TargetBootname && original.BootStatus == "good" && t.Primary == original.Name && (t.Source == "hawkbit" || t.Source == "local" && uboot.Transaction == t.ID)
}
