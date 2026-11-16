package update

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

func manifestImage(class, digest string) map[string]dbus.Variant {
	return map[string]dbus.Variant{"slot-class": dbus.MakeVariant(class), "checksum": dbus.MakeVariant(digest)}
}

func loaderFixture(t *testing.T) (*Client, *raucServiceFixture, *operation.Gate, string) {
	t.Helper()
	dir, address := filepath.Join(t.TempDir(), "state"), privateBus(t)
	f := exportFixture(t, address, dir)
	f.slots = append(f.slots, bootloaderSlots()...)
	f.manifestVersion = "loader-v9"
	f.manifestImages = []map[string]dbus.Variant{manifestImage("uboot", testRootHash), manifestImage("idb", testBootHash)}
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, false)
	c.persistent.processScan = func() (bool, bool) { return false, true }
	c.persistent.runningVersion = func() string { return "v1" }
	return c, f, gate, address
}

func (f *raucServiceFixture) finishLoader(t *testing.T, transaction string) {
	t.Helper()
	f.mu.Lock()
	f.operation = "idle"
	for _, row := range f.slots {
		class := text(row.Values, "class")
		if class != "uboot" && class != "idb" {
			continue
		}
		v := row.Values
		v["bundle.version"] = dbus.MakeVariant("loader-v9")
		v["bundle.hash"] = dbus.MakeVariant(testManifestHash)
		digest := testRootHash
		if class == "idb" {
			digest = testBootHash
		}
		v["sha256"] = dbus.MakeVariant(digest)
		v["status"] = dbus.MakeVariant("ok")
		v["installed.transaction"] = dbus.MakeVariant(transaction)
		v["installed.timestamp"] = dbus.MakeVariant(time.Now().UTC().Format(time.RFC3339))
		count, _ := v["installed.count"].Value().(uint32)
		v["installed.count"] = dbus.MakeVariant(count + 1)
	}
	f.mu.Unlock()
	if err := f.conn.Emit("/", installer+".Completed", int32(0)); err != nil {
		t.Fatal(err)
	}
}

func assertNoAutoReboot(t *testing.T, c *Client, gate *operation.Gate) {
	t.Helper()
	got, lease, err := c.PrepareAutoReboot(context.Background(), "")
	if lease != nil {
		lease.Release()
	}
	if err != nil || got.ID != "" || lease != nil {
		t.Fatalf("unexpected reboot authorization: id=%s lease=%v err=%v", got.ID, lease != nil, err)
	}
}

func TestLocalBootloaderInstallRebootAndSameOSConfirmation(t *testing.T) {
	c, f, gate, address := loaderFixture(t)
	request, err := c.InstallRequest(context.Background(), localBundle(t), "loader-local")
	if err != nil || request.TargetSlot != "rootfs.A" || request.TargetBootname != "A" || !bootloaderTask(request) {
		t.Fatalf("loader request changed OS target: %+v %v", request, err)
	}
	assertNoAutoReboot(t, c, gate)
	f.finishLoader(t, request.ID)
	observeOnce(t, c)
	installed, _ := c.Task(request.ID)
	if installed.State != InstalledPendingReboot || !verifiedRebootTask(installed) || installed.Version != "loader-v9" {
		t.Fatalf("loader installation evidence not retained: %+v", installed)
	}
	f.mu.Lock()
	if f.primary != "rootfs.A" || f.boot != "A" || f.calls != 1 || !f.journalBeforeInstall {
		t.Fatal("loader changed OS selection or bypassed durable installation")
	}
	f.mu.Unlock()
	authorized, lease, err := c.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease == nil || authorized.ID != request.ID {
		t.Fatalf("completed local loader not authorized: %+v %v", authorized, err)
	}
	lease.Release()
	dir := c.persistent.store.dir
	c.Close()
	// RAUC omits live transactions after restart; only saved verified evidence
	// may bridge that omission. The OS version intentionally differs from loader.
	f.mu.Lock()
	for _, row := range f.slots {
		delete(row.Values, "installed.transaction")
	}
	f.mu.Unlock()
	c2 := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	c2.persistent.processScan = func() (bool, bool) { return false, true }
	got, lease, err := c2.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease == nil || got.ID != request.ID {
		t.Fatalf("same-boot recovered loader did not retain reboot evidence: %+v %v", got, err)
	}
	lease.Release()
	c2.Close()
	c3 := persistentFixture(t, address, dir, "boot-two", operation.New(), false)
	c3.persistent.runningVersion = func() string { return "v1" }
	c3.persistent.bootConfirmed = func() bool { return false }
	observeOnce(t, c3)
	got, _ = c3.Task(request.ID)
	if got.State != InstalledPendingReboot {
		t.Fatal("loader confirmed before OpenRC boot check")
	}
	c3.persistent.bootConfirmed = func() bool { return true }
	observeOnce(t, c3)
	got, _ = c3.Task(request.ID)
	if got.State != BootConfirmed || got.TargetSlot != "rootfs.A" || got.Version != "loader-v9" {
		t.Fatalf("new boot did not confirm loader with unchanged OS version: %+v", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 1 {
		t.Fatal("restart replayed loader installation")
	}
}

func TestBundleImageKindsRejectMixedIncompleteAndInvalidBeforeInstall(t *testing.T) {
	cases := map[string][]map[string]dbus.Variant{
		"uboot only":     {manifestImage("uboot", testRootHash)},
		"idb only":       {manifestImage("idb", testBootHash)},
		"mixed pair":     {manifestImage("rootfs", testRootHash), manifestImage("idb", testBootHash)},
		"all four":       {manifestImage("rootfs", testRootHash), manifestImage("boot", testBootHash), manifestImage("uboot", testRootHash), manifestImage("idb", testBootHash)},
		"duplicate":      {manifestImage("uboot", testRootHash), manifestImage("uboot", testBootHash)},
		"unknown":        {manifestImage("uboot", testRootHash), manifestImage("data", testBootHash)},
		"invalid digest": {manifestImage("uboot", strings.Repeat("z", 64)), manifestImage("idb", testBootHash)},
		"extra unknown":  {manifestImage("rootfs", testRootHash), manifestImage("boot", testBootHash), manifestImage("data", testBootHash)},
	}
	for name, images := range cases {
		t.Run(name, func(t *testing.T) {
			c, f, gate, _ := loaderFixture(t)
			f.manifestImages = images
			if _, err := c.InstallRequest(context.Background(), localBundle(t), "invalid-loader"); err == nil {
				t.Fatal("invalid manifest accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.calls != 0 || gate.Busy() || len(c.persistent.tasks) != 0 {
				t.Fatal("invalid manifest reached installer or persisted an install task")
			}
		})
	}
}

func TestHawkbitBootloaderAttributionExitAndNewBoot(t *testing.T) {
	c, f, gate, address := loaderFixture(t)
	// The real run-once launcher has no version/action hint before download.
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "hawkbit-loader", Path: "/tmp/download.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	f.finishLoader(t, "updater-loader-transaction")
	observeOnce(t, c)
	installed, _ := c.Task(task.ID)
	if installed.State != InstalledPendingReboot || installed.TargetSlot != "rootfs.A" || !bootloaderTask(installed) || !verifiedRebootTask(installed) {
		t.Fatalf("external loader was not attributed: %+v", installed)
	}
	assertNoAutoReboot(t, c, gate)
	installed, err = c.EndExternal(context.Background(), task.ID, 0, nil)
	if err != nil || installed.UpdaterExit == nil || *installed.UpdaterExit != 0 {
		t.Fatalf("successful updater exit not retained: %+v %v", installed, err)
	}
	got, lease, err := c.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease == nil || got.ID != task.ID {
		t.Fatalf("successful external loader did not authorize reboot: %+v %v", got, err)
	}
	lease.Release()
	dir := c.persistent.store.dir
	c.Close()
	c2 := persistentFixture(t, address, dir, "boot-two", operation.New(), false)
	c2.persistent.bootConfirmed = func() bool { return true }
	c2.persistent.runningVersion = func() string { return "v1" }
	observeOnce(t, c2)
	got, _ = c2.Task(task.ID)
	if got.State != BootConfirmed || got.BootSlot != "A" || got.Primary != "rootfs.A" {
		t.Fatalf("external loader did not preserve/confirm original OS slot: %+v", got)
	}
}

func TestBootloaderReinstallSameVersionUsesNewTransactionAndCounters(t *testing.T) {
	for _, source := range []string{"local", "hawkbit"} {
		t.Run(source, func(t *testing.T) {
			c, f, _, _ := loaderFixture(t)
			f.finishLoader(t, "previous-loader-transaction")
			var request Task
			var err error
			if source == "local" {
				request, err = c.InstallRequest(context.Background(), localBundle(t), "reinstall-loader")
			} else {
				request, err = c.BeginExternal(context.Background(), ExternalRequest{RequestID: "reinstall-loader", Path: "/tmp/download.raucb"})
			}
			if err != nil {
				t.Fatal(err)
			}
			transaction := request.ID
			if source == "hawkbit" {
				transaction = "new-updater-loader-transaction"
			}
			f.finishLoader(t, transaction)
			if source == "hawkbit" {
				if _, err := c.EndExternal(context.Background(), request.ID, 0, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				observeOnce(t, c)
			}
			got, _ := c.Task(request.ID)
			if got.State != InstalledPendingReboot || !verifiedRebootTask(got) {
				t.Fatalf("same-content reinstall not recognized: %+v", got)
			}
			for _, installed := range got.Installed {
				before := oldSlot(got, installed.Name)
				if before.InstalledCount != 1 || installed.InstalledCount != 2 || before.SHA256 != installed.SHA256 || before.Version != installed.Version || before.Transaction == installed.Transaction {
					t.Fatalf("reinstall did not preserve old and new installation evidence: %+v %+v", before, installed)
				}
			}
		})
	}
}

func TestHawkbitBootloaderRejectsPartialMixedOrUnattributedEvidence(t *testing.T) {
	cases := map[string]func(*raucServiceFixture){
		"one image":              func(f *raucServiceFixture) { f.slots[5].Values = bootloaderSlots()[1].Values },
		"different transactions": func(f *raucServiceFixture) { f.slots[5].Values["installed.transaction"] = dbus.MakeVariant("other") },
		"old count":              func(f *raucServiceFixture) { f.slots[5].Values["installed.count"] = dbus.MakeVariant(uint32(0)) },
		"old time": func(f *raucServiceFixture) {
			f.slots[5].Values["installed.timestamp"] = dbus.MakeVariant("2020-01-01T00:00:00Z")
		},
		"wrong version": func(f *raucServiceFixture) { f.slots[5].Values["bundle.version"] = dbus.MakeVariant("other") },
		"wrong hash": func(f *raucServiceFixture) {
			f.slots[5].Values["bundle.hash"] = dbus.MakeVariant(strings.Repeat("f", 64))
		},
		"primary changed":   func(f *raucServiceFixture) { f.primary = "rootfs.B" },
		"OS record changed": func(f *raucServiceFixture) { f.slots[0].Values["installed.count"] = dbus.MakeVariant(uint32(2)) },
		"OS and loader mixed": func(f *raucServiceFixture) {
			f.primary = "rootfs.B"
			for _, row := range f.slots[2:4] {
				row.Values["bundle.version"] = dbus.MakeVariant("loader-v9")
				row.Values["bundle.hash"] = dbus.MakeVariant(testManifestHash)
				row.Values["installed.transaction"] = dbus.MakeVariant("updater-loader-transaction")
				row.Values["installed.timestamp"] = dbus.MakeVariant(time.Now().UTC().Format(time.RFC3339))
				row.Values["installed.count"] = dbus.MakeVariant(uint32(2))
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, f, gate, _ := loaderFixture(t)
			task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "bad-external-loader", Path: "/tmp/download.raucb", Version: "loader-v9", ActionID: "42"})
			if err != nil {
				t.Fatal(err)
			}
			f.finishLoader(t, "updater-loader-transaction")
			f.mu.Lock()
			change(f)
			f.mu.Unlock()
			got, err := c.EndExternal(context.Background(), task.ID, 0, nil)
			if err != nil || got.State != Unknown || len(got.Installed) != 0 {
				t.Fatalf("bad evidence attributed as installed: %+v %v", got, err)
			}
			assertNoAutoReboot(t, c, gate)
		})
	}
}

func TestHawkbitBootloaderFailedExitNeverAuthorizesReboot(t *testing.T) {
	c, f, gate, _ := loaderFixture(t)
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "failed-loader-updater", Path: "/tmp/download.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	f.finishLoader(t, "updater-loader-transaction")
	if _, err := c.EndExternal(context.Background(), task.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	assertNoAutoReboot(t, c, gate)
}
