package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

func autoRebootFixture(t *testing.T) (*Client, *raucServiceFixture, *operation.Gate, Task, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "current-boot", gate, false)
	c.persistent.processScan = func() (bool, bool) { return false, true }
	task, err := c.InstallRequest(context.Background(), localBundle(t), "auto-reboot-request")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, task.ID, 0)
	observeOnce(t, c)
	task, err = c.Task(task.ID)
	if err != nil || task.State != InstalledPendingReboot {
		t.Fatal("fixture did not create a durably verified installation")
	}
	return c, f, gate, task, address
}

func TestPrepareAutoRebootLocalAndRecoveredEvidence(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		t.Run(fmt.Sprint(recovered), func(t *testing.T) {
			c, f, gate, task, address := autoRebootFixture(t)
			if recovered {
				// RAUC Completed may be lost across Core restart. The persisted,
				// verified Installed pair, rather than result alone, is decisive.
				task.Result = nil
				if err := c.commit(task); err != nil {
					t.Fatal(err)
				}
				dir := c.persistent.store.dir
				c.Close()
				c = persistentFixture(t, address, dir, "current-boot", gate, false)
				c.persistent.processScan = func() (bool, bool) { return false, true }
				f.mu.Lock()
				for i := range f.slots {
					delete(f.slots[i].Values, "installed.transaction")
				}
				f.mu.Unlock()
			}
			before, err := os.ReadFile(filepath.Join(c.persistent.store.dir, "tasks.json"))
			if err != nil {
				t.Fatal(err)
			}
			got, lease, err := c.PrepareAutoReboot(context.Background(), "")
			if err != nil || lease == nil || got.ID != task.ID || !gate.Busy() || gate.Kind() != "update-auto-reboot" {
				t.Fatalf("did not authorize verified local task: got=%s lease=%v error=%v", got.ID, lease != nil, err)
			}
			lease.Release()
			after, err := os.ReadFile(filepath.Join(c.persistent.store.dir, "tasks.json"))
			if err != nil || string(before) != string(after) {
				t.Fatal("reboot preparation modified journal state")
			}
			f.mu.Lock()
			calls := f.calls
			statusCalls := f.statusCalls
			f.mu.Unlock()
			if calls != 1 {
				t.Fatal("reboot preparation repeated installation")
			}
			got, lease, err = c.PrepareAutoReboot(context.Background(), task.ID)
			f.mu.Lock()
			afterStatusCalls := f.statusCalls
			f.mu.Unlock()
			if err != nil || got.ID != "" || lease != nil || gate.Busy() || statusCalls != afterStatusCalls {
				t.Fatal("already attempted task repeated RAUC queries or reserved gate")
			}
		})
	}
}

func TestPrepareAutoRebootHawkbitRequiresExplicitSuccessfulExit(t *testing.T) {
	for _, exit := range []*int{nil, new(int), func() *int { n := 1; return &n }()} {
		name := "missing"
		if exit != nil {
			name = fmt.Sprint(*exit)
		}
		t.Run(name, func(t *testing.T) {
			c, _, gate, task, _ := autoRebootFixture(t)
			task.Source, task.UpdaterExit = "hawkbit", exit
			if err := c.commit(task); err != nil {
				t.Fatal(err)
			}
			got, lease, err := c.PrepareAutoReboot(context.Background(), "")
			want := exit != nil && *exit == 0
			if err != nil || (lease != nil) != want || (got.ID != "") != want || gate.Busy() != want {
				t.Fatalf("exit=%v authorized=%v error=%v", exit, lease != nil, err)
			}
			if lease != nil {
				lease.Release()
			}
		})
	}
}

func TestPrepareAutoRebootRejectsChangedOrIncompleteState(t *testing.T) {
	cases := []struct {
		name string
		task func(*Task)
		live func(*raucServiceFixture)
		scan func() (bool, bool)
	}{
		{name: "old boot", task: func(t *Task) { t.BootID = "previous-boot" }},
		{name: "failed installation result", task: func(t *Task) { n := int32(1); t.Result = &n }},
		{name: "missing persisted images", task: func(t *Task) { t.Installed = nil }},
		{name: "wrong persisted transaction", task: func(t *Task) {
			for i := range t.Installed {
				t.Installed[i].Transaction = "other"
			}
		}},
		{name: "wrong expected checksum", task: func(t *Task) { t.Images["rootfs"] = strings.Repeat("f", 64) }},
		{name: "newest task is failed", task: func(t *Task) { t.State = Failed }},
		{name: "RAUC installing", live: func(f *raucServiceFixture) { f.operation = "installing" }},
		{name: "primary changed", live: func(f *raucServiceFixture) { f.primary = "rootfs.A" }},
		{name: "target bad", live: func(f *raucServiceFixture) {
			for i := range f.slots {
				if f.slots[i].Name == "rootfs.B" {
					f.slots[i].Values["boot-status"] = dbus.MakeVariant("bad")
				}
			}
		}},
		{name: "target already running", live: func(f *raucServiceFixture) {
			f.boot = "B"
			for i := range f.slots {
				delete(f.slots[i].Values, "state")
				if f.slots[i].Name == "rootfs.B" {
					f.slots[i].Values["state"] = dbus.MakeVariant("booted")
				}
			}
		}},
		{name: "ambiguous boot state", live: func(f *raucServiceFixture) {
			for i := range f.slots {
				if f.slots[i].Name == "rootfs.B" {
					f.slots[i].Values["state"] = dbus.MakeVariant("booted")
				}
			}
		}},
		{name: "changed target checksum", live: func(f *raucServiceFixture) {
			for i := range f.slots {
				if f.slots[i].Name == "rootfs.B" {
					f.slots[i].Values["sha256"] = dbus.MakeVariant(strings.Repeat("f", 64))
				}
			}
		}},
		{name: "updater exists", scan: func() (bool, bool) { return true, true }},
		{name: "updater scan incomplete", scan: func() (bool, bool) { return false, false }},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			c, f, gate, task, _ := autoRebootFixture(t)
			if fixture.task != nil {
				fixture.task(&task)
				if err := c.commit(task); err != nil {
					t.Fatal(err)
				}
			}
			if fixture.live != nil {
				f.mu.Lock()
				fixture.live(f)
				f.mu.Unlock()
			}
			if fixture.scan != nil {
				c.persistent.processScan = fixture.scan
			}
			got, lease, err := c.PrepareAutoReboot(context.Background(), "")
			if err != nil || got.ID != "" || lease != nil || gate.Busy() {
				t.Fatalf("unsafe task authorized: id=%s lease=%v err=%v", got.ID, lease != nil, err)
			}
		})
	}
}

func TestPrepareAutoRebootFailuresAndOtherGateDoNotAuthorize(t *testing.T) {
	c, f, gate, _, _ := autoRebootFixture(t)
	lease, err := gate.TryAcquire("recovery")
	if err != nil {
		t.Fatal(err)
	}
	got, granted, err := c.PrepareAutoReboot(context.Background(), "")
	if err != nil || granted != nil || got.ID != "" || gate.Kind() != "recovery" {
		t.Fatal("reboot preparation interfered with existing operation")
	}
	lease.Release()
	c.persistent.active = "updater-awaiting-feedback"
	_, granted, err = c.PrepareAutoReboot(context.Background(), "")
	if err != nil || granted != nil || gate.Busy() {
		t.Fatal("active updater lifecycle authorized reboot")
	}
	c.persistent.active = ""
	c.persistent.saveError = fmt.Errorf("%w: fixture disk failure", ErrPersistence)
	_, granted, err = c.PrepareAutoReboot(context.Background(), "")
	if !errors.Is(err, ErrPersistence) || granted != nil || gate.Busy() {
		t.Fatal("unpersisted journal authorized reboot")
	}
	c.persistent.saveError = nil
	if err := f.conn.Export(nil, "/", installer); err != nil {
		t.Fatal(err)
	}
	_, granted, err = c.PrepareAutoReboot(context.Background(), "")
	if err == nil || granted != nil || gate.Busy() {
		t.Fatal("RAUC method failure authorized reboot or leaked lease")
	}
	if err := f.conn.Export(f, "/", installer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, granted, err = c.PrepareAutoReboot(ctx, "")
	if !errors.Is(err, context.Canceled) || granted != nil || gate.Busy() {
		t.Fatal("cancelled preparation authorized reboot")
	}
}

func TestPrepareAutoRebootOnlyLatestTask(t *testing.T) {
	c, _, _, task, _ := autoRebootFixture(t)
	newest := cloneTask(task)
	newest.ID, newest.RequestID, newest.State = "newest-failed", "newest-request", Failed
	if err := c.commit(newest); err != nil {
		t.Fatal(err)
	}
	got, lease, err := c.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease != nil || got.ID != "" {
		t.Fatal("older task selected past a newer failed request")
	}
}

func TestPrepareAutoRebootHasSingleConcurrentWinner(t *testing.T) {
	c, _, gate, _, _ := autoRebootFixture(t)
	var wg sync.WaitGroup
	leases := make(chan *operation.Lease, 2)
	errorsSeen := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, granted, err := c.PrepareAutoReboot(context.Background(), "")
			if granted != nil {
				leases <- granted
			}
			if err != nil {
				errorsSeen <- err
			}
		}()
	}
	wg.Wait()
	close(leases)
	close(errorsSeen)
	count := 0
	for granted := range leases {
		count++
		granted.Release()
	}
	for err := range errorsSeen {
		t.Error(err)
	}
	if count != 1 || gate.Busy() {
		t.Fatalf("concurrent reboot authorizations=%d", count)
	}
}
