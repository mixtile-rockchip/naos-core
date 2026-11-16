package update

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

func bootloaderSlots() []slotTuple {
	return []slotTuple{
		{Name: "uboot.0", Values: map[string]dbus.Variant{
			"class": dbus.MakeVariant("uboot"), "device": dbus.MakeVariant("/dev/naos/uboot"), "state": dbus.MakeVariant("inactive"),
		}},
		{Name: "idb.0", Values: map[string]dbus.Variant{
			"class": dbus.MakeVariant("idb"), "device": dbus.MakeVariant("/dev/naos/disk"), "state": dbus.MakeVariant("inactive"),
		}},
	}
}

func TestBootloaderSlotsPreserveOSChecksAndInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	f.slots = append(f.slots, bootloaderSlots()...)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), true)
	c.persistent.processScan = func() (bool, bool) { return false, true }

	check := beginCheck(t, c, "empty-with-bootloaders")
	if len(check.Before) != 6 || !checkTopology(check.Before) {
		t.Fatal("shared bootloader slots were lost or rejected")
	}
	finished, err := c.EndExternal(context.Background(), check.ID, 0, nil)
	if err != nil || !emptyCheck(finished) {
		t.Fatalf("unchanged bootloader slots made an empty check uncertain: %s %q %v", finished.State, finished.Error, err)
	}

	task, err := c.InstallRequest(context.Background(), localBundle(t), "os-with-bootloaders")
	if err != nil {
		t.Fatal(err)
	}
	if task.TargetSlot != "rootfs.B" || len(task.Before) != 6 {
		t.Fatal("bootloader slots altered the OS target or baseline")
	}
	f.finish(t, task.ID, 0)
	installed := waitTask(t, c, task.ID, InstalledPendingReboot)
	if len(installed.Installed) != 2 {
		t.Fatal("shared bootloader slots became OS installation evidence")
	}
	for _, slot := range installed.Installed {
		if slot.Class != "rootfs" && slot.Class != "boot" {
			t.Fatalf("unexpected installed OS slot: %+v", slot)
		}
	}

	baseline := snapshot{BootSlot: check.BootSlot, Primary: check.Primary, Slots: append([]SlotEvidence(nil), check.Before...)}
	baseline.Slots[4].InstalledCount++
	if unchangedCheck(check, baseline) {
		t.Fatal("a changed bootloader record was discarded as an empty check")
	}
}

func TestBootloaderSlotTopologyRejectsUnexpectedSlots(t *testing.T) {
	base := []SlotEvidence{
		{Name: "rootfs.A", Class: "rootfs", Device: "/dev/os-a", Bootname: "A", State: "booted", BootStatus: "good"},
		{Name: "boot.A", Class: "boot", Device: "/dev/boot-a", Parent: "rootfs.A", State: "active"},
		{Name: "rootfs.B", Class: "rootfs", Device: "/dev/os-b", Bootname: "B", State: "inactive", BootStatus: "good"},
		{Name: "boot.B", Class: "boot", Device: "/dev/boot-b", Parent: "rootfs.B", State: "inactive"},
		{Name: "idb.0", Class: "idb", Device: "/dev/naos/disk", State: "inactive"},
		{Name: "uboot.0", Class: "uboot", Device: "/dev/naos/uboot", State: "inactive"},
	}
	if !checkTopology(base[:4]) || !checkTopology(base) {
		t.Fatal("expected OS topology with optional bootloader slots")
	}
	for _, tc := range []struct {
		name   string
		change func([]SlotEvidence) []SlotEvidence
	}{
		{"unknown class", func(s []SlotEvidence) []SlotEvidence { s[4].Class = "data"; return s }},
		{"extra copy", func(s []SlotEvidence) []SlotEvidence { s[4].Name = "idb.1"; return s }},
		{"wrong disk", func(s []SlotEvidence) []SlotEvidence { s[4].Device = "/dev/other-disk"; return s }},
		{"wrong uboot", func(s []SlotEvidence) []SlotEvidence { s[5].Device = "/dev/other-uboot"; return s }},
		{"OS child", func(s []SlotEvidence) []SlotEvidence { s[4].Parent = "rootfs.B"; return s }},
		{"bootname", func(s []SlotEvidence) []SlotEvidence { s[4].Bootname = "C"; return s }},
		{"boot status", func(s []SlotEvidence) []SlotEvidence { s[4].BootStatus = "good"; return s }},
		{"active", func(s []SlotEvidence) []SlotEvidence { s[4].State = "active"; return s }},
		{"booted", func(s []SlotEvidence) []SlotEvidence { s[4].State = "booted"; return s }},
		{"duplicate device", func(s []SlotEvidence) []SlotEvidence { s[0].Device = s[4].Device; return s }},
		{"duplicate slot", func(s []SlotEvidence) []SlotEvidence { return append(s, s[4]) }},
		{"missing OS child", func(s []SlotEvidence) []SlotEvidence { return append(s[:3], s[4:]...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if checkTopology(tc.change(append([]SlotEvidence(nil), base...))) {
				t.Fatal("unexpected topology accepted")
			}
		})
	}
}
