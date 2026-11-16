package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

func outcomeFixture() (Task, snapshot) {
	stamp := "2026-11-03T00:00:00Z"
	root := SlotEvidence{Name: "rootfs.B", Class: "rootfs", Bootname: "B", Status: "ok", BootStatus: "good", Version: "v2", ManifestHash: testManifestHash, SHA256: testRootHash, Transaction: "saved-transaction", InstalledAt: stamp, InstalledCount: 2}
	boot := SlotEvidence{Name: "boot.B", Class: "boot", Parent: root.Name, Status: "ok", Version: "v2", ManifestHash: testManifestHash, SHA256: testBootHash, Transaction: root.Transaction, InstalledAt: stamp, InstalledCount: 2}
	original := SlotEvidence{Name: "rootfs.A", Class: "rootfs", Bootname: "A", State: "booted", BootStatus: "good"}
	task := Task{ID: "saved-transaction", RequestID: "outcome-request", Source: "local", Path: "/tmp/test.raucb", State: InstalledPendingReboot, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), BootID: "boot-before", BootSlot: "A", Primary: root.Name, TargetSlot: root.Name, TargetBootname: "B", Version: root.Version, ManifestHash: root.ManifestHash, Before: []SlotEvidence{original}, Installed: []SlotEvidence{root, boot}}
	result := int32(0)
	task.Result = &result
	return task, snapshot{BootSlot: "A", Primary: root.Name, Slots: []SlotEvidence{original, root, boot}}
}

func replacement(s snapshot, missingTransaction bool) snapshot {
	out := s
	out.Slots = append([]SlotEvidence(nil), s.Slots...)
	for i := range out.Slots {
		v := &out.Slots[i]
		if v.Name == "rootfs.B" || v.Parent == "rootfs.B" {
			v.Transaction = "replacement-transaction"
			if missingTransaction {
				v.Transaction = ""
			}
			v.InstalledCount++
			v.InstalledAt = "2026-11-03T00:00:01Z"
		}
	}
	return out
}

func bootTarget(s snapshot) snapshot {
	out := s
	out.Slots = append([]SlotEvidence(nil), s.Slots...)
	out.BootSlot = "B"
	for i := range out.Slots {
		out.Slots[i].State = ""
		if out.Slots[i].Name == "rootfs.B" {
			out.Slots[i].State = "booted"
		}
	}
	return out
}

func TestPendingBootOutcomeEvidenceMatrix(t *testing.T) {
	cases := []struct {
		name, bootID, want, prefix string
		change                     func(*snapshot)
		confirmed                  bool
		version                    string
	}{
		{"same boot waits for reboot", "boot-before", InstalledPendingReboot, "", nil, false, "v1"},
		{"new target waits for mark good", "boot-after", InstalledPendingReboot, "", func(s *snapshot) { *s = bootTarget(*s) }, false, "v2"},
		{"new target waits for lower", "boot-after", InstalledPendingReboot, "", func(s *snapshot) { *s = bootTarget(*s) }, true, "v1"},
		{"new target confirmed", "boot-after", BootConfirmed, "", func(s *snapshot) { *s = bootTarget(*s) }, true, "v2"},
		{"contradictory boot never confirms", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { *s = bootTarget(*s); s.BootSlot = "A" }, true, "v2"},
		{"returned original target bad", "boot-after", Failed, "BOOT_ROLLED_BACK:", func(s *snapshot) { s.Primary = "rootfs.A"; s.Slots[1].BootStatus = "bad" }, false, "v1"},
		{"original with target good is unproven", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { s.Primary = "rootfs.A" }, false, "v1"},
		{"original without primary evidence", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { s.Slots[1].BootStatus = "bad" }, false, "v1"},
		{"original not good", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) {
			s.Primary = "rootfs.A"
			s.Slots[0].BootStatus = "bad"
			s.Slots[1].BootStatus = "bad"
		}, false, "v1"},
		{"multiple booted roots", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { s.Slots[1].State = "booted"; s.Slots[1].BootStatus = "bad" }, false, "v1"},
		{"boot slot contradicts state", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { s.BootSlot = "B"; s.Primary = "rootfs.A"; s.Slots[1].BootStatus = "bad" }, false, "v1"},
		{"missing target record", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { s.Slots = s.Slots[:1] }, false, "v1"},
		{"target boot with changed incomplete cohort", "boot-after", Unknown, "BOOT_RESULT_UNKNOWN:", func(s *snapshot) { *s = bootTarget(*s); s.Slots[1].InstalledCount++ }, false, "v2"},
		{"same bundle replaced same boot", "boot-before", Failed, "SUPERSEDED:", func(s *snapshot) { *s = replacement(*s, false) }, false, "v1"},
		{"replacement after RAUC restart lacks transaction", "boot-after", Failed, "SUPERSEDED:", func(s *snapshot) { *s = bootTarget(replacement(*s, true)) }, true, "v2"},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			task, live := outcomeFixture()
			if fixture.change != nil {
				fixture.change(&live)
			}
			gate := operation.New()
			c := &Client{}
			if err := c.initPersistent(filepath.Join(t.TempDir(), "state"), gate, fixture.bootID, false); err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.persistent.bootConfirmed = func() bool { return fixture.confirmed }
			c.persistent.runningVersion = func() string { return fixture.version }
			if err := c.commit(task); err != nil {
				t.Fatal(err)
			}
			if err := c.settlePending(live); err != nil {
				t.Fatal(err)
			}
			got, err := c.Task(task.ID)
			if err != nil || got.State != fixture.want || !strings.HasPrefix(got.Error, fixture.prefix) || got.Result == nil || *got.Result != 0 || gate.Busy() {
				t.Fatalf("outcome state=%s error=%q result=%v gate=%v err=%v", got.State, got.Error, got.Result, gate.Busy(), err)
			}
			if got.State == InstalledPendingReboot && (!got.UpdatedAt.Equal(task.UpdatedAt) || got.BootSlot != task.BootSlot) {
				t.Fatal("waiting path rewrote pending task or original boot evidence")
			}
		})
	}
}

func TestSupersededRequiresCompletePositiveReplacementEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*snapshot)
	}{
		{"one unchanged count", func(s *snapshot) { s.Slots[2].InstalledCount-- }},
		{"timestamp moved backwards", func(s *snapshot) { s.Slots[1].InstalledAt = "2026-11-02T23:59:59Z" }},
		{"missing timestamp", func(s *snapshot) { s.Slots[1].InstalledAt = "" }},
		{"missing checksum", func(s *snapshot) { s.Slots[2].SHA256 = "" }},
		{"missing version", func(s *snapshot) { s.Slots[1].Version = "" }},
		{"inconsistent versions", func(s *snapshot) { s.Slots[1].Version = "v3" }},
		{"inconsistent manifest hashes", func(s *snapshot) { s.Slots[1].ManifestHash = strings.Repeat("f", 64) }},
		{"only one missing transaction", func(s *snapshot) { s.Slots[2].Transaction = "" }},
		{"old transaction retained", func(s *snapshot) {
			s.Slots[1].Transaction = "saved-transaction"
			s.Slots[2].Transaction = "saved-transaction"
		}},
		{"different transactions", func(s *snapshot) { s.Slots[2].Transaction = "other" }},
		{"failed image", func(s *snapshot) { s.Slots[2].Status = "failed" }},
		{"missing boot image", func(s *snapshot) { s.Slots = s.Slots[:2] }},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			task, live := outcomeFixture()
			live = replacement(live, false)
			fixture.change(&live)
			if superseded(task, live) {
				t.Fatal("incomplete or contradictory installation was called superseded")
			}
		})
	}
}

func TestManagedReplacementSettlesOldTaskViaRealDBusAndPersistsCompatibleJournal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "same-boot", gate, false)
	path := localBundle(t)
	old, err := c.InstallRequest(context.Background(), path, "original-request")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, old.ID, 0)
	observeOnce(t, c)
	newer, err := c.InstallRequest(context.Background(), path, "new-request")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, newer.ID, 0)
	// Both installations may finish within one timestamp second. A distinct
	// transaction plus higher counters still proves same-bundle replacement.
	f.mu.Lock()
	for i := range f.slots {
		if f.slots[i].Name == "rootfs.B" || f.slots[i].Name == "boot.B" {
			f.slots[i].Values["installed.count"] = dbus.MakeVariant(uint32(3))
		}
	}
	f.mu.Unlock()
	observeOnce(t, c)
	got, _ := c.Task(old.ID)
	current, _ := c.Task(newer.ID)
	if got.State != Failed || !strings.HasPrefix(got.Error, "SUPERSEDED:") || current.State != InstalledPendingReboot || gate.Busy() {
		t.Fatalf("old=%s/%q current=%s gate=%v", got.State, got.Error, current.State, gate.Busy())
	}
	// The old format-1 reader used exactly these states, rejected unknown JSON
	// fields and did not know any new outcome enum. Preserve that wire shape.
	data, err := os.ReadFile(filepath.Join(dir, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var legacy journal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err != nil || legacy.Format != 1 {
		t.Fatalf("legacy journal decode: %v", err)
	}
	allowed := map[string]bool{"submitted": true, "installing": true, "running_external": true, "installed_pending_reboot": true, "boot_confirmed": true, "failed": true, "unknown": true}
	for _, record := range legacy.Tasks {
		if !allowed[record.State] {
			t.Fatalf("old reader rejects new enum %q", record.State)
		}
	}
	c.Close()
	after := persistentFixture(t, address, dir, "same-boot", gate, false)
	again, err := after.InstallRequest(context.Background(), path, "original-request")
	if err != nil || again.ID != old.ID || again.State != Failed || gate.Busy() {
		t.Fatalf("restart changed completed idempotent task: %+v %v", again, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 2 {
		t.Fatalf("restart repeated InstallBundle: calls=%d", f.calls)
	}
}

func TestUnprovenBootOutcomeDoesNotReopenOrPollAfterRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	_ = exportFixture(t, address, dir)
	task, live := outcomeFixture()
	c := persistentFixture(t, address, dir, "boot-after", operation.New(), false)
	if err := c.commit(task); err != nil {
		t.Fatal(err)
	}
	if err := c.settlePending(live); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Task(task.ID)
	if got.State != Unknown || !resolvedBootOutcome(got) {
		t.Fatalf("unproven return to original slot: %+v", got)
	}
	c.Close()
	gate := operation.New()
	after := persistentFixture(t, address, dir, "boot-after", gate, true)
	// No RAUC connection should even be opened for a terminal historical
	// observation, so the observer's next natural tick must remain inactive.
	time.Sleep(1100 * time.Millisecond)
	after.mu.Lock()
	connected, active := after.conn != nil, after.persistent.active
	after.mu.Unlock()
	if connected || active != "" || gate.Busy() {
		t.Fatal("terminal unknown boot outcome restarted RAUC polling or retained a gate")
	}
	again, err := after.InstallRequest(context.Background(), task.Path, task.RequestID)
	if err != nil || again.State != Unknown || again.Error != got.Error {
		t.Fatalf("lost durable unknown outcome or idempotency: %+v %v", again, err)
	}
}

func TestTransientRAUCReadFailureDoesNotClassifyPendingBoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-before", operation.New(), false)
	task, err := c.InstallRequest(context.Background(), localBundle(t), "transient-outcome")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, task.ID, 0)
	observeOnce(t, c)
	c.Close()
	gate := operation.New()
	after := persistentFixture(t, address, dir, "boot-after", gate, false)
	// Real D-Bus error rather than an incomplete/empty synthetic slot snapshot.
	if err := f.conn.Export(nil, "/", installer); err != nil {
		t.Fatal(err)
	}
	after.mu.Lock()
	status, err := after.status(context.Background())
	if err == nil {
		err = after.reconcile(context.Background(), status)
	}
	after.mu.Unlock()
	if err == nil {
		t.Fatal("fixture did not produce a real RAUC method error")
	}
	got, _ := after.Task(task.ID)
	if got.State != InstalledPendingReboot || got.Error != "" || gate.Busy() {
		t.Fatalf("transient read failure invented boot outcome: %+v", got)
	}
	if err := f.conn.Export(f, "/", installer); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.primary = "rootfs.A"
	for i := range f.slots {
		if f.slots[i].Name == "rootfs.B" {
			f.slots[i].Values["boot-status"] = dbus.MakeVariant("bad")
		}
	}
	f.mu.Unlock()
	observeOnce(t, after)
	got, _ = after.Task(task.ID)
	if got.State != Failed || !strings.HasPrefix(got.Error, "BOOT_ROLLED_BACK:") || got.Result == nil || *got.Result != 0 || gate.Busy() {
		t.Fatalf("rollback did not settle after the read recovered: %+v", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 1 {
		t.Fatal("boot reconciliation replayed installation")
	}
}

func TestTerminalOutcomeDoesNotReleaseAnotherOperation(t *testing.T) {
	task, live := outcomeFixture()
	gate := operation.New()
	lease, err := gate.TryAcquire("reboot")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	c := &Client{}
	if err := c.initPersistent(filepath.Join(t.TempDir(), "state"), gate, "boot-after", false); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.commit(task); err != nil {
		t.Fatal(err)
	}
	if err := c.settlePending(live); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.TryAcquire("local-update"); !errors.Is(err, operation.ErrBusy) || gate.Kind() != "reboot" {
		t.Fatal("history reconciliation released an unrelated operation")
	}
}

func TestFailedPartialReplacementSettlesEarlierTaskWithoutPollingSameBoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "same-boot", gate, false)
	path := localBundle(t)
	old, err := c.InstallRequest(context.Background(), path, "old-before-partial")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, old.ID, 0)
	observeOnce(t, c)
	newer, err := c.InstallRequest(context.Background(), path, "new-fails-partway")
	if err != nil {
		t.Fatal(err)
	}
	// The slot may change during writes; never classify it while RAUC is busy.
	f.mu.Lock()
	for i := range f.slots {
		if f.slots[i].Name == "rootfs.B" {
			f.slots[i].Values["sha256"] = dbus.MakeVariant(strings.Repeat("f", 64))
			f.slots[i].Values["installed.count"] = dbus.MakeVariant(uint32(3))
		}
	}
	f.mu.Unlock()
	observeOnce(t, c)
	stillPending, _ := c.Task(old.ID)
	if stillPending.State != InstalledPendingReboot {
		t.Fatal("RAUC writing caused a premature terminal outcome")
	}
	f.finish(t, newer.ID, 1)
	observeOnce(t, c)
	got, _ := c.Task(old.ID)
	failed, _ := c.Task(newer.ID)
	if got.State != Unknown || !resolvedBootOutcome(got) || got.Result == nil || *got.Result != 0 || failed.State != Failed || failed.Result == nil || *failed.Result != 1 || gate.Busy() {
		t.Fatalf("partial replacement outcome old=%s/%q newer=%s gate=%v", got.State, got.Error, failed.State, gate.Busy())
	}
}

func TestResolvedExternalOutcomeCannotBeReenteredByHooks(t *testing.T) {
	task, _ := outcomeFixture()
	task.Source, task.State, task.Error = "hawkbit", Unknown, bootUnknownError
	gate := operation.New()
	c := &Client{}
	if err := c.initPersistent(filepath.Join(t.TempDir(), "state"), gate, "boot-after", false); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.commit(task); err != nil {
		t.Fatal(err)
	}
	got, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: task.RequestID, Path: task.Path})
	if err != nil || got.State != Unknown || got.Error != task.Error || gate.Busy() || c.conn != nil {
		t.Fatalf("repeated BeginExternal reopened terminal observation: %+v %v", got, err)
	}
	got, err = c.EndExternal(context.Background(), task.ID, 0, nil)
	if err != nil || got.State != Unknown || got.Error != task.Error || got.UpdaterExit == nil || *got.UpdaterExit != 0 || gate.Busy() || c.conn != nil {
		t.Fatalf("late EndExternal overwrote terminal observation: %+v %v", got, err)
	}
}

func TestConfirmedHistoryIsNeverDowngraded(t *testing.T) {
	task, live := outcomeFixture()
	task.State = BootConfirmed
	c := &Client{}
	if err := c.initPersistent(filepath.Join(t.TempDir(), "state"), operation.New(), "later-boot", false); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.commit(task); err != nil {
		t.Fatal(err)
	}
	if err := c.settlePending(replacement(live, false)); err != nil {
		t.Fatal(err)
	}
	got, _ := c.Task(task.ID)
	if got.State != BootConfirmed || got.Error != "" || !got.UpdatedAt.Equal(task.UpdatedAt) {
		t.Fatal("later slot changes rewrote confirmed history")
	}
}
