package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

const testManifestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testRootHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testBootHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

type raucServiceFixture struct {
	mu                       sync.Mutex
	conn                     *dbus.Conn
	operation, boot, primary string
	slots                    []slotTuple
	calls                    int
	statusCalls              int
	options                  map[string]dbus.Variant
	dir                      string
	journalBeforeInstall     bool
	manifestImages           []map[string]dbus.Variant
	manifestVersion          string
}

func (f *raucServiceFixture) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	if iface != installer {
		return nil, dbus.MakeFailedError(errors.New("unknown interface"))
	}
	return map[string]dbus.Variant{"Operation": dbus.MakeVariant(f.operation), "LastError": dbus.MakeVariant(""), "BootSlot": dbus.MakeVariant(f.boot), "Progress": dbus.MakeVariant(Progress{Percentage: 50, Message: "fixture progress", Depth: 1})}, nil
}
func (f *raucServiceFixture) GetPrimary() (string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.primary, nil
}
func (f *raucServiceFixture) GetSlotStatus() ([]slotTuple, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]slotTuple, len(f.slots))
	for i, s := range f.slots {
		values := map[string]dbus.Variant{}
		for k, v := range s.Values {
			values[k] = v
		}
		out[i] = slotTuple{s.Name, values}
	}
	return out, nil
}
func (f *raucServiceFixture) InspectBundle(path string, options map[string]dbus.Variant) (map[string]dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(options) != 0 {
		return nil, dbus.MakeFailedError(errors.New("unsafe inspect options"))
	}
	images, version := f.manifestImages, f.manifestVersion
	if images == nil {
		images = []map[string]dbus.Variant{{"slot-class": dbus.MakeVariant("rootfs"), "checksum": dbus.MakeVariant(testRootHash)}, {"slot-class": dbus.MakeVariant("boot"), "checksum": dbus.MakeVariant(testBootHash)}}
	}
	if version == "" {
		version = "v2"
	}
	return map[string]dbus.Variant{"manifest-hash": dbus.MakeVariant(testManifestHash), "update": dbus.MakeVariant(dbus.MakeVariant(map[string]dbus.Variant{"version": dbus.MakeVariant(version)})), "images": dbus.MakeVariant(dbus.MakeVariant(images))}, nil
}
func (f *raucServiceFixture) InstallBundle(path string, options map[string]dbus.Variant) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.options = options
	data, _ := os.ReadFile(filepath.Join(f.dir, "tasks.json"))
	id, _ := options["transaction-id"].Value().(string)
	f.journalBeforeInstall = id != "" && strings.Contains(string(data), id) && options["require-manifest-hash"].Value() == testManifestHash
	if !f.journalBeforeInstall || len(options) != 2 {
		return dbus.MakeFailedError(errors.New("journal missing or unsafe options"))
	}
	f.operation = "installing"
	return nil
}
func (f *raucServiceFixture) finish(t *testing.T, transaction string, result int32) {
	t.Helper()
	f.mu.Lock()
	f.operation = "idle"
	if result == 0 {
		f.primary = "rootfs.B"
		for i := range f.slots {
			if f.slots[i].Name == "rootfs.B" || f.slots[i].Name == "boot.B" {
				v := f.slots[i].Values
				v["bundle.version"] = dbus.MakeVariant("v2")
				v["bundle.hash"] = dbus.MakeVariant(testManifestHash)
				hash := testRootHash
				if f.slots[i].Name == "boot.B" {
					hash = testBootHash
				}
				v["sha256"] = dbus.MakeVariant(hash)
				v["status"] = dbus.MakeVariant("ok")
				v["installed.transaction"] = dbus.MakeVariant(transaction)
				v["installed.timestamp"] = dbus.MakeVariant(time.Now().UTC().Format(time.RFC3339))
				v["installed.count"] = dbus.MakeVariant(uint32(2))
			}
		}
	}
	f.mu.Unlock()
	if err := f.conn.Emit("/", installer+".Completed", result); err != nil {
		t.Fatal(err)
	}
}
func privateBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}
func exportFixture(t *testing.T, address, dir string) *raucServiceFixture {
	t.Helper()
	conn, err := dbus.Dial(address)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.Auth(nil); err != nil {
		t.Fatal(err)
	}
	if err = conn.Hello(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if _, err = conn.RequestName(service, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	f := &raucServiceFixture{conn: conn, operation: "idle", boot: "A", primary: "rootfs.A", dir: dir}
	for _, letter := range []string{"A", "B"} {
		for _, class := range []string{"rootfs", "boot"} {
			v := map[string]dbus.Variant{"class": dbus.MakeVariant(class), "status": dbus.MakeVariant("ok"), "bundle.version": dbus.MakeVariant("v1"), "bundle.hash": dbus.MakeVariant(strings.Repeat("d", 64)), "sha256": dbus.MakeVariant(strings.Repeat("e", 64)), "installed.transaction": dbus.MakeVariant("old-" + letter), "installed.timestamp": dbus.MakeVariant("2020-01-01T00:00:00Z"), "installed.count": dbus.MakeVariant(uint32(1))}
			v["device"] = dbus.MakeVariant("/dev/fixture-" + class + "-" + letter)
			v["state"] = dbus.MakeVariant("inactive")
			if class == "rootfs" {
				v["bootname"] = dbus.MakeVariant(letter)
				v["boot-status"] = dbus.MakeVariant("good")
				if letter == "A" {
					v["state"] = dbus.MakeVariant("booted")
				}
			} else {
				v["parent"] = dbus.MakeVariant("rootfs." + letter)
				if letter == "A" {
					v["state"] = dbus.MakeVariant("active")
				}
			}
			f.slots = append(f.slots, slotTuple{class + "." + letter, v})
		}
	}
	if err = conn.Export(f, "/", installer); err != nil {
		t.Fatal(err)
	}
	if err = conn.Export(f, "/", properties); err != nil {
		t.Fatal(err)
	}
	return f
}
func persistentFixture(t *testing.T, address, dir, boot string, gate *operation.Gate, background bool) *Client {
	t.Helper()
	c := &Client{busAddress: address}
	if err := c.initPersistent(dir, gate, boot, background); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func localBundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signed-by-fixture.raucb")
	if err := os.WriteFile(path, []byte("DBus fixture, not a real signed bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func observeOnce(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	status, err := c.status(ctx)
	if err == nil {
		err = c.reconcile(ctx, status)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func waitTask(t *testing.T, c *Client, id, state string) Task {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		task, err := c.Task(id)
		if err != nil {
			t.Fatal(err)
		}
		if task.State == state {
			return task
		}
		time.Sleep(10 * time.Millisecond)
	}
	task, _ := c.Task(id)
	t.Fatalf("task state %s, want %s: %+v", task.State, state, task)
	return Task{}
}

func TestPersistentInstallRealDBusIdempotencyAndBackgroundCompletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, true)
	path := localBundle(t)
	task, err := c.InstallRequest(context.Background(), path, "req-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.InstallRequest(context.Background(), path, "req-1")
	if err != nil || again.ID != task.ID {
		t.Fatalf("duplicate changed identity: %+v %v", again, err)
	}
	if _, err := c.InstallRequest(context.Background(), path+"-other", "req-1"); !errors.Is(err, ErrRequestConflict) {
		t.Fatalf("expected request conflict, got %v", err)
	}
	if _, err := gate.TryAcquire("reboot"); !errors.Is(err, operation.ErrBusy) {
		t.Fatal("install did not reserve operation gate")
	}
	f.mu.Lock()
	calls, queued := f.calls, f.journalBeforeInstall
	f.mu.Unlock()
	if calls != 1 || !queued {
		t.Fatalf("Install calls=%d durable-before-call=%v", calls, queued)
	}
	f.finish(t, task.ID, 0)
	finished := waitTask(t, c, task.ID, InstalledPendingReboot)
	if len(finished.Installed) != 2 || finished.Version != "v2" {
		t.Fatalf("lost installation evidence: %+v", finished)
	}
	if busy, err := c.Busy(context.Background()); err != nil || busy {
		t.Fatalf("installation did not release guard: %v %v", busy, err)
	}
	for _, name := range []string{dir, filepath.Join(dir, "tasks.json")} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if name == dir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s permissions %o", name, info.Mode().Perm())
		}
	}
}
func TestRestartRecoversByTransactionWithoutReinstallOrInventingBootGood(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	task, err := c.InstallRequest(context.Background(), localBundle(t), "recovered")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	f.finish(t, task.ID, 0)
	c2 := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	observeOnce(t, c2)
	got, err := c2.Task(task.ID)
	if err != nil || got.State != InstalledPendingReboot {
		t.Fatalf("recovery: %+v %v", got, err)
	}
	f.mu.Lock()
	if f.calls != 1 {
		t.Fatal("restart submitted installation again")
	}
	f.boot = "B"
	for i := range f.slots {
		if f.slots[i].Name == "rootfs.A" {
			delete(f.slots[i].Values, "state")
		}
		if f.slots[i].Name == "rootfs.B" {
			f.slots[i].Values["state"] = dbus.MakeVariant("booted")
		}
	}
	f.mu.Unlock()
	c2.Close()
	c3 := persistentFixture(t, address, dir, "boot-two", operation.New(), false)
	c3.persistent.runningVersion = func() string { return "v2" }
	c3.persistent.bootConfirmed = func() bool { return false }
	observeOnce(t, c3)
	got, _ = c3.Task(task.ID)
	if got.State != InstalledPendingReboot {
		t.Fatal("good RAUC flag alone falsely confirmed boot")
	}
	c3.persistent.bootConfirmed = func() bool { return true }
	c3.persistent.runningVersion = func() string { return "wrong" }
	observeOnce(t, c3)
	got, _ = c3.Task(task.ID)
	if got.State != InstalledPendingReboot {
		t.Fatal("wrong lower version falsely confirmed boot")
	}
	c3.persistent.runningVersion = func() string { return "v2" }
	observeOnce(t, c3)
	got, _ = c3.Task(task.ID)
	if got.State != BootConfirmed {
		t.Fatalf("verified new boot was not confirmed: %+v", got)
	}
}
func TestMissingRecoveryEvidenceBecomesUnknownAndNeverReplays(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	task, err := c.InstallRequest(context.Background(), localBundle(t), "lost")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	f.mu.Lock()
	f.operation = "idle"
	f.mu.Unlock()
	gate := operation.New()
	c2 := persistentFixture(t, address, dir, "boot-one", gate, false)
	c2.persistent.lastProgress = time.Now().Add(-time.Minute)
	observeOnce(t, c2)
	got, _ := c2.Task(task.ID)
	if got.State != Unknown || got.Result != nil || gate.Busy() {
		t.Fatalf("uncertain result invented or retained Busy: %+v", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 1 {
		t.Fatal("unproven task reinstalled")
	}
}
func TestDurabilityFailureNeverCallsInstall(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, false)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.InstallRequest(context.Background(), localBundle(t), "no-durable-state"); !errors.Is(err, ErrPersistence) {
		t.Fatalf("not classified persistence failure: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 0 || gate.Busy() {
		t.Fatal("undurable request reached installer or left gate held")
	}
}
func TestExternalExitZeroNeverImpliesInstalledAndGateCoversDownload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	_ = exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, false)
	req := ExternalRequest{Source: "hawkbit", RequestID: "action-no-install", Path: "/tmp/download.raucb"}
	task, err := c.BeginExternal(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.BeginExternal(context.Background(), req)
	if err != nil || again.ID != task.ID {
		t.Fatalf("external duplicate: %+v %v", again, err)
	}
	if _, err := c.InstallRequest(context.Background(), localBundle(t), "local-race"); !errors.Is(err, ErrBusy) {
		t.Fatal("external download did not block local install")
	}
	result, err := c.EndExternal(context.Background(), task.ID, 0, nil)
	if err != nil || result.State != Unknown || result.Result != nil || gate.Busy() {
		t.Fatalf("exit0 became installed or stuck busy: %+v %v", result, err)
	}
}
func TestExternalInstallationRequiresNewCohortEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "action-real-install", Path: "/tmp/download.raucb", Version: "v2", ActionID: "42"})
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, "updater-generated-transaction", 0)
	result, err := c.EndExternal(context.Background(), task.ID, 0, nil)
	if err != nil || result.State != InstalledPendingReboot || len(result.Installed) != 2 {
		t.Fatalf("external evidence not recovered: %+v %v", result, err)
	}
}

func selfIdentity(t *testing.T, boot string) ExternalIdentity {
	t.Helper()
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndex(string(data), ") ")
	fields := strings.Fields(string(data[end+2:]))
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "updater.conf")
	content := []byte("test configuration, no real credentials")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return ExternalIdentity{PID: os.Getpid(), StartTime: start, BootID: boot, Exe: exe, ConfigPath: path, ConfigSHA256: hex.EncodeToString(sum[:])}
}
func TestExternalGateSurvivesRealDBusLossWhileProcessAlive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, false)
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "alive-outage", Path: "/tmp/download.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	identity := selfIdentity(t, "boot-one")
	if err := c.AttachExternal(context.Background(), task.ID, identity); err != nil {
		t.Fatal(err)
	}
	f.conn.Close()
	// Actual D-Bus owner loss. Fast-forward the bounded observation grace; the
	// live process must keep ownership even after installation status is unknown.
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("closed RAUC owner unexpectedly answered")
	}
	c.mu.Lock()
	c.observationUnavailable()
	c.mu.Unlock()
	got, _ := c.Task(task.ID)
	if got.State != Unknown || !gate.Busy() {
		t.Fatalf("live external process lost its lease: %+v", got)
	}
	if _, err := gate.TryAcquire("recovery"); !errors.Is(err, operation.ErrBusy) {
		t.Fatal("recovery raced an alive external task")
	}
	// Begin with the same persisted request re-adopts the original task rather
	// than admitting a second process, even after the RAUC uncertainty transition.
	same, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "alive-outage", Path: "/tmp/download.raucb"})
	if err != nil || same.ID != task.ID {
		t.Fatalf("external adoption: %+v %v", same, err)
	}
	_, _ = c.EndExternal(context.Background(), task.ID, -1, errors.New("fixture process ended"))
	if gate.Busy() {
		t.Fatal("EndExternal retained lease after the process ended")
	}
}
func TestJournalRetentionPermissionsAndCorruption(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	c := &Client{}
	if err := c.initPersistent(dir, operation.New(), "boot-one", false); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		task := Task{ID: fmt.Sprintf("task-%d", i), RequestID: fmt.Sprintf("req-%d", i), Source: "local", State: Failed, CreatedAt: now, UpdatedAt: now}
		if err := c.commit(task); err != nil {
			t.Fatal(err)
		}
	}
	tasks, err := c.Tasks()
	if err != nil || len(tasks) != 32 || tasks[0].ID != "task-39" {
		t.Fatalf("retention: %d %v", len(tasks), err)
	}
	if _, err := c.Task("task-0"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("evicted task still present")
	}
	_, loaded, err := openStore(dir)
	if err != nil || len(loaded) != 32 {
		t.Fatalf("load retained journal: %d %v", len(loaded), err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tasks.json"), []byte(`{"format":1,"tasks":[`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openStore(dir); err == nil {
		t.Fatal("corrupt journal was silently discarded")
	}
}
func TestMismatchedTransactionCannotClaimSuccessfulInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	f := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	task, err := c.InstallRequest(context.Background(), localBundle(t), "wrong-txn")
	if err != nil {
		t.Fatal(err)
	}
	f.finish(t, "someone-elses-install", 0)
	c.persistent.lastProgress = time.Now().Add(-time.Minute)
	observeOnce(t, c)
	got, _ := c.Task(task.ID)
	if got.State != Unknown {
		t.Fatalf("unrelated installation claimed as ours: %+v", got)
	}
}

func TestUnattachedExternalLaunchGapDoesNotStayBusyAfterRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	_ = exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-one", operation.New(), false)
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "crash-before-spawn", Path: "/tmp/download.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	gate := operation.New()
	c2 := persistentFixture(t, address, dir, "boot-one", gate, false)
	c2.persistent.lastProgress = time.Now().Add(-time.Minute)
	c2.persistent.processScan = func() (bool, bool) { return false, true } // explicit empty proc-scan boundary
	observeOnce(t, c2)
	got, _ := c2.Task(task.ID)
	if got.State != Unknown || gate.Busy() {
		t.Fatalf("missing worker stayed permanently busy: %+v", got)
	}
}
func TestRecordedExternalProcessGoneIsResolvedWithoutEndCallback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	_ = exportFixture(t, address, dir)
	gate := operation.New()
	c := persistentFixture(t, address, dir, "boot-one", gate, false)
	task, err := c.BeginExternal(context.Background(), ExternalRequest{RequestID: "old-worker-gone", Path: "/tmp/download.raucb"})
	if err != nil {
		t.Fatal(err)
	}
	identity := selfIdentity(t, "boot-one")
	if err := c.AttachExternal(context.Background(), task.ID, identity); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	record, _ := c.findTask(task.ID)
	record.ExternalIdentity.StartTime++
	if err := c.commit(record); err != nil {
		t.Fatal(err)
	}
	c.persistent.lastProgress = time.Now().Add(-time.Minute)
	c.mu.Unlock()
	observeOnce(t, c)
	got, _ := c.Task(task.ID)
	if got.State != Unknown || got.UpdaterExit != nil || gate.Busy() {
		t.Fatalf("dead old worker required unavailable exit code: %+v", got)
	}
}

func TestBootConfirmationAfterRAUCRestartOmitsLiveTransaction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	address := privateBus(t)
	original := exportFixture(t, address, dir)
	c := persistentFixture(t, address, dir, "boot-before", operation.New(), false)
	task, err := c.InstallRequest(context.Background(), localBundle(t), "rauc-reload-transaction")
	if err != nil {
		t.Fatal(err)
	}
	original.finish(t, task.ID, 0)
	observeOnce(t, c)
	verified, err := c.Task(task.ID)
	if err != nil || verified.State != InstalledPendingReboot || len(verified.Installed) != 2 || verified.Installed[0].Transaction != task.ID {
		t.Fatalf("missing initial verified installation: %+v %v", verified, err)
	}
	c.Close()
	// Reproduce the pinned RAUC status-file loader: all persisted image/time/
	// counter fields return on D-Bus after restart, except installed.transaction.
	original.mu.Lock()
	saved := make([]slotTuple, len(original.slots))
	for i, row := range original.slots {
		values := map[string]dbus.Variant{}
		for k, v := range row.Values {
			if k != "installed.transaction" {
				values[k] = v
			}
		}
		delete(values, "state")
		if row.Name == "rootfs.B" {
			values["state"] = dbus.MakeVariant("booted")
		}
		saved[i] = slotTuple{Name: row.Name, Values: values}
	}
	original.mu.Unlock()
	original.conn.Close()
	restarted := exportFixture(t, address, dir)
	restarted.mu.Lock()
	restarted.slots = saved
	restarted.boot = "B"
	restarted.primary = "rootfs.B"
	restarted.mu.Unlock()
	after := persistentFixture(t, address, dir, "boot-after", operation.New(), false)
	after.persistent.runningVersion = func() string { return "v2" }
	after.persistent.bootConfirmed = func() bool { return true }
	observeOnce(t, after)
	got, _ := after.Task(task.ID)
	if got.State != BootConfirmed {
		t.Fatalf("valid boot stuck after missing RAUC transaction: %+v", got)
	}
	restarted.mu.Lock()
	defer restarted.mu.Unlock()
	if restarted.calls != 0 {
		t.Fatal("boot confirmation reinstalled the bundle")
	}
}

func TestMissingLiveTransactionRequiresExactPersistedInstallationEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	verified := Task{ID: "verified-local-task", Source: "local", Version: "v2", ManifestHash: testManifestHash, BootID: "old-boot", TargetSlot: "rootfs.B", TargetBootname: "B", Installed: []SlotEvidence{
		{Name: "rootfs.B", Class: "rootfs", Bootname: "B", Version: "v2", ManifestHash: testManifestHash, SHA256: testRootHash, Transaction: "verified-local-task", InstalledAt: now, InstalledCount: 2, Status: "ok"},
		{Name: "boot.B", Class: "boot", Parent: "rootfs.B", Version: "v2", ManifestHash: testManifestHash, SHA256: testBootHash, Transaction: "verified-local-task", InstalledAt: now, InstalledCount: 2, Status: "ok"},
	}}
	live := snapshot{BootSlot: "B", Primary: "rootfs.B", Slots: append([]SlotEvidence(nil), verified.Installed...)}
	for i := range live.Slots {
		live.Slots[i].Transaction = ""
	}
	live.Slots[0].State = "booted"
	live.Slots[0].BootStatus = "good"
	if !sameInstalledEvidence(verified, live) {
		t.Fatal("complete persisted evidence did not tolerate missing live transaction")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SlotEvidence)
	}{
		{"slot", func(s *SlotEvidence) { s.Name = "rootfs.other" }},
		{"version", func(s *SlotEvidence) { s.Version = "another-version" }},
		{"manifest", func(s *SlotEvidence) { s.ManifestHash = strings.Repeat("f", 64) }},
		{"checksum", func(s *SlotEvidence) { s.SHA256 = strings.Repeat("f", 64) }},
		{"timestamp", func(s *SlotEvidence) { s.InstalledAt = "2020-01-01T00:00:00Z" }},
		{"count", func(s *SlotEvidence) { s.InstalledCount++ }},
		{"status", func(s *SlotEvidence) { s.Status = "failed" }},
		{"different-live-transaction", func(s *SlotEvidence) { s.Transaction = "another-installation" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := live
			changed.Slots = append([]SlotEvidence(nil), live.Slots...)
			tc.mutate(&changed.Slots[0])
			if sameInstalledEvidence(verified, changed) {
				t.Fatal("different or incomplete installation was treated as the verified one")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SlotEvidence)
	}{
		{"missing-record-transaction", func(s *SlotEvidence) { s.Transaction = "" }},
		{"missing-record-timestamp", func(s *SlotEvidence) { s.InstalledAt = "" }},
		{"missing-record-count", func(s *SlotEvidence) { s.InstalledCount = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloneTask(verified)
			tc.mutate(&changed.Installed[0])
			if sameInstalledEvidence(changed, live) {
				t.Fatal("unverified persistent evidence allowed confirmation")
			}
		})
	}
	// The compatibility rule is solely for post-boot checking of an already
	// verified snapshot; fresh local/external attribution still requires txn.
	for _, source := range []string{"local", "hawkbit"} {
		fresh := cloneTask(verified)
		fresh.Source = source
		fresh.Installed = nil
		fresh.CreatedAt = time.Now().Add(-time.Minute)
		if _, ok := installedEvidence(fresh, live); ok {
			t.Fatalf("fresh %s installation inferred from transaction-free status", source)
		}
	}
}
