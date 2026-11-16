package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, resets bool) string {
	t.Helper()
	root := t.TempDir()
	entry := filepath.Join(root, "watchdog0")
	if err := os.MkdirAll(filepath.Join(entry, "device", "of_node"), 0700); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"dev": "242:0", "identity": "Synopsys DesignWare Watchdog", "state": "inactive", "nowayout": "0", "timeout": "44"} {
		if err := os.WriteFile(filepath.Join(entry, k), []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/sys/bus/platform/drivers/dw_wdt", filepath.Join(entry, "device", "driver")); err != nil {
		t.Fatal(err)
	}
	if resets {
		if err := os.WriteFile(filepath.Join(entry, "device", "of_node", "resets"), []byte{0, 0, 0, 1}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestInspectWithoutResetNeverApprovesExercise(t *testing.T) {
	root := fixture(t, false)
	calls := 0
	r, err := inspectWith("/dev/watchdog0", root, func(string) (uint64, error) { calls++; return 0xf200, nil })
	if err != nil || calls != 1 || r.Driver != "dw_wdt" || r.Nowayout == nil || *r.Nowayout || r.HardwareStopSupported == nil || *r.HardwareStopSupported {
		t.Fatal("missing reset capability not reported")
	}
	if err := ValidateExercise(r); err == nil {
		t.Fatal("non-stoppable driver approved")
	}
	device := newFake()
	if d, err := openExerciseWith(device, r); err == nil || d != nil || device.openCount != 0 {
		t.Fatal("unsupported preflight reached device open")
	}
}
func TestInspectChecksIdentityNumberAndLegacyAlias(t *testing.T) {
	root := fixture(t, true)
	if _, err := inspectWith("/dev/watchdog0", root, func(string) (uint64, error) { return 0xa82, nil }); err == nil {
		t.Fatal("wrong device number accepted")
	}
	if _, err := inspectWith("/dev/watchdog", root, func(string) (uint64, error) { t.Fatal("legacy alias reached validator"); return 0, nil }); err == nil {
		t.Fatal("legacy alias accepted")
	}
	r, err := inspectWith("/dev/watchdog0", root, func(string) (uint64, error) { return 0xf200, nil })
	if err != nil || r.HardwareStopSupported == nil || !*r.HardwareStopSupported {
		t.Fatal("reset path not read")
	}
	if err := ValidateExercise(r); err != nil {
		t.Fatal(err)
	}
	r.State = "active"
	if err := ValidateExercise(r); err == nil {
		t.Fatal("active device takeover approved")
	}
	r.State = "inactive"
	yes := true
	r.Nowayout = &yes
	if err := ValidateExercise(r); err == nil {
		t.Fatal("nowayout device approved")
	}
	r.Nowayout = nil
	if err := ValidateExercise(r); err == nil {
		t.Fatal("unknown nowayout approved")
	}
}
