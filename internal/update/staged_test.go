package update

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

func historyFixture(t *testing.T) (*Client, *raucServiceFixture, *operation.Gate, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "current-boot", gate, false)
	c.persistent.processScan = func() (bool, bool) { return false, true }
	for i := 0; i < maxTasks; i++ {
		task, _ := outcomeFixture()
		task.ID, task.RequestID = fmt.Sprintf("real-install-%02d", i), fmt.Sprintf("real-request-%02d", i)
		task.State, task.BootID = BootConfirmed, "historical-boot"
		for j := range task.Installed {
			task.Installed[j].Transaction = task.ID
		}
		if err := c.commit(task); err != nil {
			t.Fatal(err)
		}
	}
	return c, f, gate, address
}

func historyBytes(t *testing.T, c *Client) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.persistent.store.dir, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func beginCheck(t *testing.T, c *Client, request string) Task {
	t.Helper()
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: request, Path: "/tmp/updater.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func factorySlots(f *raucServiceFixture, onlyB bool) {
	for i := range f.slots {
		if onlyB && !strings.HasSuffix(f.slots[i].Name, ".B") {
			continue
		}
		for _, key := range []string{"status", "bundle.version", "bundle.hash", "sha256", "installed.transaction", "installed.timestamp", "installed.count"} {
			delete(f.slots[i].Values, key)
		}
	}
}

func TestEmptyChecksPreserveAll32RealTasksIncludingFactoryBaselines(t *testing.T) {
	for _, baseline := range []string{"installed", "factory", "mixed"} {
		t.Run(baseline, func(t *testing.T) {
			c, f, gate, address := historyFixture(t)
			f.mu.Lock()
			if baseline != "installed" {
				factorySlots(f, baseline == "mixed")
			}
			f.mu.Unlock()
			before := historyBytes(t, c)
			var previous string
			for i := 0; i < 40; i++ {
				task := beginCheck(t, c, fmt.Sprintf("empty-%d", i))
				if !gate.Busy() || string(historyBytes(t, c)) != string(before) {
					t.Fatal("Begin evicted real history or failed to guard updater")
				}
				records, err := c.persistent.store.read(pendingJournal, 1)
				if err != nil || len(records) != 1 || records[0].ID != task.ID {
					t.Fatalf("running check is not durable: %v", err)
				}
				all, err := c.Tasks()
				if err != nil || len(all) != 33 || all[0].ID != task.ID {
					t.Fatal("runtime task or one of 32 real tasks is hidden")
				}
				if _, err := c.Task("real-install-00"); err != nil {
					t.Fatal("oldest real installation disappeared during a check")
				}
				if previous != "" {
					if _, err := c.EndExternal(context.Background(), previous, 0, nil); err != nil || !gate.Busy() || c.persistent.active != task.ID {
						t.Fatal("late empty callback altered newer updater lease")
					}
				}
				f.mu.Lock()
				for left, right := 0, len(f.slots)-1; left < right; left, right = left+1, right-1 {
					f.slots[left], f.slots[right] = f.slots[right], f.slots[left]
				}
				f.mu.Unlock()
				got, err := c.EndExternal(context.Background(), task.ID, 0, nil)
				if err != nil || !emptyCheck(got) || gate.Busy() || string(historyBytes(t, c)) != string(before) {
					t.Fatalf("empty check changed history: %s %q %v", got.State, got.Error, err)
				}
				if _, err := c.Task(task.ID); !errors.Is(err, ErrNotFound) {
					t.Fatal("empty task remained in formal history")
				}
				if _, err := os.Lstat(filepath.Join(c.persistent.store.dir, pendingJournal)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("empty pending file was not removed")
				}
				previous = task.ID
			}
			dir := c.persistent.store.dir
			c.Close()
			after := persistentFixture(t, address, dir, "current-boot", operation.New(), false)
			all, err := after.Tasks()
			if err != nil || len(all) != 32 || string(historyBytes(t, after)) != string(before) || after.persistent.active != "" {
				t.Fatal("restart lost 32 real records or restarted an empty check")
			}
			f.mu.Lock()
			calls := f.calls
			f.mu.Unlock()
			if calls != 0 {
				t.Fatal("empty check replayed installation")
			}
		})
	}
}

func TestUnprovenChecksRemainFormalHistory(t *testing.T) {
	cases := []struct {
		name          string
		before        func(*raucServiceFixture)
		after         func(*raucServiceFixture)
		duringInstall bool
		completed     bool
		code          int
		runErr        error
	}{
		{name: "exit nonzero", code: 1},
		{name: "exit zero with run error", runErr: errors.New("process wait failed")},
		{name: "observed installing", duringInstall: true},
		{name: "completed signal", completed: true},
		{name: "transaction lost", after: func(f *raucServiceFixture) {
			for i := range f.slots {
				delete(f.slots[i].Values, "installed.transaction")
			}
		}},
		{name: "slot changed", after: func(f *raucServiceFixture) { f.slots[0].Values["installed.count"] = dbus.MakeVariant(uint32(2)) }},
		{name: "primary changed", after: func(f *raucServiceFixture) { f.primary = "rootfs.B" }},
		{name: "partial factory record", before: func(f *raucServiceFixture) {
			factorySlots(f, false)
			f.slots[0].Values["bundle.version"] = dbus.MakeVariant("partial")
		}},
		{name: "unknown factory status", before: func(f *raucServiceFixture) {
			factorySlots(f, false)
			f.slots[0].Values["status"] = dbus.MakeVariant("unknown")
		}},
		{name: "invalid topology", before: func(f *raucServiceFixture) { delete(f.slots[0].Values, "device") }},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			c, f, gate, _ := historyFixture(t)
			f.mu.Lock()
			if fixture.before != nil {
				fixture.before(f)
			}
			f.mu.Unlock()
			before := historyBytes(t, c)
			task := beginCheck(t, c, "unproven-check")
			if fixture.duringInstall {
				f.mu.Lock()
				f.operation = "installing"
				f.mu.Unlock()
				observeOnce(t, c)
				f.mu.Lock()
				f.operation = "idle"
				f.mu.Unlock()
			}
			f.mu.Lock()
			if fixture.after != nil {
				fixture.after(f)
			}
			f.mu.Unlock()
			if fixture.completed {
				if err := f.conn.Emit("/", installer+".Completed", int32(0)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := c.EndExternal(context.Background(), task.ID, fixture.code, fixture.runErr)
			if err != nil || emptyCheck(got) || (got.State != Unknown && got.State != Failed) || gate.Busy() || string(historyBytes(t, c)) == string(before) {
				t.Fatalf("unproven check was discarded: %s %q %v", got.State, got.Error, err)
			}
			if saved, err := c.Task(task.ID); err != nil || saved.State != got.State {
				t.Fatal("uncertain task is not in formal history")
			}
		})
	}
}

func TestPendingCheckCrashRecoveryAndPromotionResidue(t *testing.T) {
	for _, promoted := range []bool{false, true} {
		t.Run(fmt.Sprint(promoted), func(t *testing.T) {
			c, _, gate, address := historyFixture(t)
			task := beginCheck(t, c, "crash-check")
			dir := c.persistent.store.dir
			if promoted {
				task.State, task.Error = Failed, "durable failure"
				exit := -1
				task.UpdaterExit = &exit
				history := append(append([]Task(nil), c.persistent.tasks...), task)
				if err := c.persistent.store.save(history[1:]); err != nil {
					t.Fatal(err)
				}
			}
			c.Close()
			after := persistentFixture(t, address, dir, "current-boot", gate, false)
			after.persistent.processScan = func() (bool, bool) { return false, true }
			got, err := after.Task(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if promoted {
				if got.State != Failed || got.Error != "durable failure" || after.persistent.external != nil || gate.Busy() {
					t.Fatal("old sidecar replaced primary durable failure")
				}
			} else {
				if got.State != RunningExternal || !gate.Busy() {
					t.Fatal("restart lost pending check or its guard")
				}
				after.persistent.lastProgress = time.Now().Add(-time.Minute)
				observeOnce(t, after)
				got, err = after.Task(task.ID)
				if err != nil || got.State != Unknown || emptyCheck(got) || gate.Busy() {
					t.Fatal("missing old exit code was treated as an empty check")
				}
			}
		})
	}
}

func TestInstalledExternalPromotesAndAutoRebootSurvivesEmptyCheck(t *testing.T) {
	c, f, gate, _ := historyFixture(t)
	task := beginCheck(t, c, "real-update")
	f.finish(t, task.ID, 0)
	observeOnce(t, c)
	if got, err := c.Task(task.ID); err != nil || got.State != InstalledPendingReboot {
		t.Fatal("real install did not promote")
	}
	if _, err := c.EndExternal(context.Background(), task.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	if c.persistent.external != nil || gate.Busy() {
		t.Fatal("real install left pending journal or lease")
	}
	got, lease, err := c.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease == nil || got.ID != task.ID {
		t.Fatalf("real OTA auto reboot lost after promotion: %v", err)
	}
	lease.Release()
	// A later ordinary empty check must not hide the installed task from the
	// auto reboot selector. Its before/after primary is now the target B.
	check := beginCheck(t, c, "empty-after-real")
	if _, lease, err := c.PrepareAutoReboot(context.Background(), ""); err != nil || lease != nil {
		t.Fatal("reboot authorized while check was active")
	}
	if got, err := c.EndExternal(context.Background(), check.ID, 0, nil); err != nil || !emptyCheck(got) {
		t.Fatalf("ordinary check was not empty: %v", err)
	}
	got, lease, err = c.PrepareAutoReboot(context.Background(), "")
	if err != nil || lease == nil || got.ID != task.ID {
		t.Fatal("empty check disrupted successful update reboot")
	}
	lease.Release()
}

func TestPendingCleanupFailuresStayGuardedUntilExactRetry(t *testing.T) {
	for _, boundary := range []string{"unlink", "directory-sync"} {
		t.Run(boundary, func(t *testing.T) {
			c, _, gate, _ := historyFixture(t)
			before := historyBytes(t, c)
			task := beginCheck(t, c, "cleanup-fails")
			store := c.persistent.store
			if boundary == "unlink" {
				store.removePending = func(string) error { return os.ErrPermission }
			} else {
				failed := false
				store.syncDirectory = func() error {
					if _, err := os.Lstat(filepath.Join(store.dir, pendingJournal)); errors.Is(err, os.ErrNotExist) && !failed {
						failed = true
						return errors.New("directory sync fixture")
					}
					return nil
				}
			}
			if _, err := c.EndExternal(context.Background(), task.ID, 0, nil); !errors.Is(err, ErrPersistence) || !gate.Busy() || c.persistent.external == nil || string(historyBytes(t, c)) != string(before) {
				t.Fatal("failed cleanup discarded request, changed history, or released guard")
			}
			if _, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "must-wait", Path: "/tmp/new.raucb"}); !errors.Is(err, ErrBusy) {
				t.Fatal("new check overwrote failed cleanup")
			}
			store.removePending = nil
			observeOnce(t, c)
			if gate.Busy() || c.persistent.external != nil || c.persistent.saveError != nil || string(historyBytes(t, c)) != string(before) {
				t.Fatal("cleanup retry failed to finish exact sidecar protocol")
			}
		})
	}
}

func TestInvalidPendingJournalRejectedAndBeginWriteFailurePreservesHistory(t *testing.T) {
	for _, kind := range []string{"corrupt", "permissions", "multiple", "empty"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _, _ := historyFixture(t)
			dir := c.persistent.store.dir
			c.Close()
			path := filepath.Join(dir, pendingJournal)
			if kind == "multiple" {
				task, _ := outcomeFixture()
				task.Source, task.State = "hawkbit", RunningExternal
				if err := (&taskStore{dir: dir}).saveFile(pendingJournal, []Task{task, task}, 2); err != nil {
					t.Fatal(err)
				}
			} else {
				mode := os.FileMode(0600)
				if kind == "permissions" {
					mode = 0644
				}
				data := []byte(`{"format":1,"tasks":[`)
				if kind == "empty" {
					data = []byte(`{"format":1,"tasks":[]}`)
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			after := &Client{}
			if err := after.initPersistent(dir, operation.New(), "current-boot", false); err == nil {
				after.Close()
				t.Fatal("invalid sidecar was silently dropped")
			}
		})
	}
	c, _, gate, _ := historyFixture(t)
	before := historyBytes(t, c)
	path := filepath.Join(c.persistent.store.dir, pendingJournal)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "write-fails", Path: "/tmp/download.raucb"}); !errors.Is(err, ErrPersistence) || !gate.Busy() || string(historyBytes(t, c)) != string(before) {
		t.Fatal("failed stage write lost real history or claimed acceptance")
	}
}

func TestExplicitDeploymentHintsAreNotDiscardedAsEmpty(t *testing.T) {
	for _, version := range []bool{false, true} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			c, _, gate, _ := historyFixture(t)
			req := ExternalRequest{RequestID: "known-action", Path: "/tmp/download.raucb"}
			if version {
				req.Version = "expected-version"
			} else {
				req.ActionID = "known-action-id"
			}
			task, err := c.BeginExternal(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.EndExternal(context.Background(), task.ID, 0, nil)
			if err != nil || got.State != Unknown || emptyCheck(got) || gate.Busy() {
				t.Fatal("explicit deployment context was discarded as an ordinary check")
			}
			if _, err := c.Task(task.ID); err != nil {
				t.Fatal("unproven deployment task did not enter formal history")
			}
		})
	}
}

func TestFailedPromotionKeepsDurableSidecarUntilMainHistoryCanBeSaved(t *testing.T) {
	c, _, gate, address := historyFixture(t)
	task := beginCheck(t, c, "promotion-write-fails")
	dir := c.persistent.store.dir
	main, backup := filepath.Join(dir, "tasks.json"), filepath.Join(dir, "saved-history.json")
	before := historyBytes(t, c)
	if err := os.Rename(main, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(main, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EndExternal(context.Background(), task.ID, 1, errors.New("failed child")); !errors.Is(err, ErrPersistence) || !gate.Busy() {
		t.Fatal("failed main promotion lost pending task or guard")
	}
	pending, err := c.persistent.store.read(pendingJournal, 1)
	if err != nil || len(pending) != 1 || pending[0].ID != task.ID || pending[0].State != Failed {
		t.Fatal("terminal evidence was not preserved in sidecar")
	}
	old, err := os.ReadFile(backup)
	if err != nil || string(old) != string(before) {
		t.Fatal("promotion failure damaged previous 32 histories")
	}
	if err := os.Remove(main); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, main); err != nil {
		t.Fatal(err)
	}
	// A process restart completes the saved promotion, rather than starting
	// a replacement updater or losing the failed operation.
	c.Close()
	after := persistentFixture(t, address, dir, "current-boot", gate, false)
	got, err := after.Task(task.ID)
	if err != nil || got.State != Failed || got.UpdaterExit == nil || *got.UpdaterExit != 1 || after.persistent.external != nil || gate.Busy() {
		t.Fatalf("promotion recovery: %+v %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, pendingJournal)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful promotion recovery left a stale sidecar")
	}
}

func TestReapedUpdaterExitHandoffDoesNotPromoteEmptyCheckToUnknown(t *testing.T) {
	for _, deliverExit := range []bool{true, false} {
		t.Run(fmt.Sprint(deliverExit), func(t *testing.T) {
			c, _, gate, _ := historyFixture(t)
			before := historyBytes(t, c)
			task := beginCheck(t, c, "reaped-child-handoff")
			child := exec.Command("/bin/sh", "-c", "printf 'ready\n'; read line; exit 0")
			input, err := child.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = child.Process.Kill() })
			if ready, err := bufio.NewReader(output).ReadString('\n'); err != nil || ready != "ready\n" {
				t.Fatalf("child not ready: %q %v", ready, err)
			}
			identity := selfIdentity(t, "current-boot")
			identity.PID = child.Process.Pid
			prefix := "/proc/" + strconv.Itoa(identity.PID)
			data, err := os.ReadFile(prefix + "/stat")
			if err != nil {
				t.Fatal(err)
			}
			end := strings.LastIndex(string(data), ") ")
			fields := strings.Fields(string(data[end+2:]))
			identity.StartTime, err = strconv.ParseUint(fields[19], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			identity.Exe, err = os.Readlink(prefix + "/exe")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AttachExternal(context.Background(), task.ID, identity); err != nil {
				t.Fatal(err)
			}
			// Simulate a long download whose Begin time is long past. The last
			// observation of the live child, rather than Begin, starts the grace.
			c.persistent.lastProgress = time.Now().Add(-time.Hour)
			observeOnce(t, c)
			if time.Since(c.persistent.lastProgress) > time.Second {
				t.Fatal("live worker did not refresh handoff window")
			}
			if _, err := input.Write([]byte("finish\n")); err != nil {
				t.Fatal(err)
			}
			_ = input.Close()
			if err := child.Wait(); err != nil {
				t.Fatal(err)
			}
			// Deterministic reproduction: Wait has completed but EndExternal has
			// deliberately not run. The observer must not publish Unknown yet.
			observeOnce(t, c)
			waiting, err := c.Task(task.ID)
			if err != nil || waiting.State != RunningExternal || waiting.UpdaterExit != nil || !gate.Busy() || string(historyBytes(t, c)) != string(before) {
				t.Fatal("observer beat the normal exit handoff and evicted upgrade history")
			}
			if deliverExit {
				got, err := c.EndExternal(context.Background(), task.ID, 0, nil)
				if err != nil || !emptyCheck(got) || gate.Busy() || string(historyBytes(t, c)) != string(before) {
					t.Fatal("delivered clean exit did not finish as an empty check")
				}
			} else {
				// A lost old callback is not recovered or invented. Only the bounded
				// handoff grace delays Unknown; expiry must release the operation.
				c.persistent.lastProgress = time.Now().Add(-6 * time.Second)
				observeOnce(t, c)
				got, err := c.Task(task.ID)
				if err != nil || got.State != Unknown || emptyCheck(got) || got.UpdaterExit != nil || gate.Busy() {
					t.Fatal("missing exit callback stayed busy or fabricated an empty result")
				}
			}
		})
	}
}
