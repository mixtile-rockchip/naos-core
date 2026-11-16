package hawkbit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

func TestMain(m *testing.M) {
	if os.Getenv("NAOS_HB_FIXTURE_MODE") == "updater" {
		if len(os.Args) != 4 || os.Args[1] != "--config-file" || os.Args[3] != "--run-once" {
			os.Exit(7)
		}
		f, _ := os.OpenFile(os.Getenv("NAOS_HB_FIXTURE_COUNT"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if f != nil {
			fmt.Fprintln(f, "start")
			f.Close()
		}
		fmt.Fprintln(os.Stdout, "fixture-secret-token")
		fmt.Fprintln(os.Stderr, "fixture progress 77% is not a supported download protocol")
		d, _ := time.ParseDuration(os.Getenv("NAOS_HB_FIXTURE_DELAY"))
		time.Sleep(d)
		fmt.Fprintln(os.Stdout, "No new software.")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type hookFixture struct {
	mu             sync.Mutex
	tasks          map[string]string
	ends, attaches int
	identity       ProcessIdentity
}

func (h *hookFixture) hooks() Hooks {
	return Hooks{
		BeginExternal: func(_ context.Context, r ExternalRequest) (string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.tasks == nil {
				h.tasks = map[string]string{}
			}
			id := fmt.Sprintf("task-%d", len(h.tasks)+1)
			h.tasks[r.RequestID] = id
			return id, nil
		},
		AttachExternal: func(_ context.Context, _ string, i ProcessIdentity) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.attaches++
			h.identity = i
			return nil
		},
		EndExternal: func(context.Context, string, int, error) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.ends++
			return nil
		},
	}
}
func setupRunner(t *testing.T, cfg config.HawkbitConfig, hooks Hooks, directory, delay string) *Runner {
	t.Helper()
	r, err := New(cfg, hooks, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	r.options.directory, r.options.updater, r.options.monitorInterval = directory, exe, 20*time.Millisecond
	r.options.childEnv = append(os.Environ(), "NAOS_HB_FIXTURE_MODE=updater", "NAOS_HB_FIXTURE_DELAY="+delay, "NAOS_HB_FIXTURE_COUNT="+filepath.Join(directory, "starts"))
	return r
}
func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true before deadline")
}

func TestHeartbeatDuringUpdaterAndCompletionBasedScheduling(t *testing.T) {
	var polls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		polls.Add(1)
		io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:01"}}}`)
	}))
	defer s.Close()
	cfg := fixtureConfig(t, s.URL)
	h := &hookFixture{}
	directory := filepath.Join(t.TempDir(), "runtime")
	r := setupRunner(t, cfg, h.hooks(), directory, "1500ms")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	defer cancel()
	eventually(t, 6*time.Second, func() bool {
		return r.Snapshot().Updater.Phase == "completed" && !r.Snapshot().Updater.NextRun.IsZero()
	})
	status := r.Snapshot()
	if status.State != "running" {
		t.Fatalf("active scheduler state: %s", status.State)
	}
	if err := r.Run(ctx); err == nil || r.Snapshot().State != "running" {
		t.Fatal("duplicate Run changed the active scheduler state")
	}
	if polls.Load() < 2 || status.Updater.NextRun.Before(status.Updater.CompletedAt.Add(time.Second)) || status.Updater.NextRun.Sub(status.Updater.StartedAt) < 2*time.Second {
		t.Fatal("heartbeat stalled or schedule did not start after completion")
	}
	if status.Updater.DownloadPercent != nil {
		t.Fatal("invented download progress")
	}
	content, _ := os.ReadFile(filepath.Join(directory, "starts"))
	if string(content) != "start\n" {
		t.Fatal("overlapping updater")
	}
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), cfg.Token) {
		t.Fatal("snapshot exposed token")
	}
	info, _ := os.Stat(logPath(directory))
	if info.Mode().Perm() != 0600 {
		t.Fatal("updater log is not private")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r.Snapshot().State != "stopped" {
		t.Fatal("cancelled scheduler did not report stopped")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ends != 1 || len(h.tasks) != 1 {
		t.Fatal("external task count differs")
	}
}

func TestCoreStopDoesNotKillAndNextRunnerOnlySkipsExistingUpdater(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:01"}}}`)
	}))
	defer s.Close()
	cfg := fixtureConfig(t, s.URL)
	h := &hookFixture{}
	directory := filepath.Join(t.TempDir(), "runtime")
	first := setupRunner(t, cfg, h.hooks(), directory, "1200ms")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- first.Run(ctx) }()
	eventually(t, 3*time.Second, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.attaches > 0 })
	eventually(t, 3*time.Second, func() bool {
		data, _ := os.ReadFile(filepath.Join(directory, "starts"))
		return string(data) == "start\n"
	})
	pid := first.Snapshot().Updater.PID
	identity, err := processIdentity(pid)
	if err != nil {
		t.Fatal(err)
	}
	iniBefore, _ := os.ReadFile(configPath(directory))
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current, err := processIdentity(pid)
	if err != nil || current.StartTime != identity.StartTime {
		t.Fatal("Core stop killed updater")
	}
	active, err := hasRunningUpdater(first.options.updater)
	if err != nil || !active {
		t.Fatal("existing updater not detected")
	}
	second := setupRunner(t, cfg, h.hooks(), directory, "1ms")
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- second.Run(ctx2) }()
	eventually(t, time.Second, func() bool { return second.Snapshot().Updater.Phase == "skipped" })
	if second.Snapshot().Updater.PID != 0 || second.Snapshot().Updater.TaskID != "" {
		t.Fatal("new Core adopted old updater instead of skipping")
	}
	iniAfter, _ := os.ReadFile(configPath(directory))
	if string(iniBefore) != string(iniAfter) {
		t.Fatal("skipped interval rewrote active INI")
	}
	cancel2()
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(filepath.Join(directory, "starts"))
	if string(content) != "start\n" {
		t.Fatal("new Core reissued updater")
	}
	h.mu.Lock()
	if len(h.tasks) != 1 || h.ends != 0 {
		h.mu.Unlock()
		t.Fatal("new Core resumed an old external task")
	}
	h.mu.Unlock()
	eventually(t, 5*time.Second, func() bool { _, err := processIdentity(pid); return err != nil })
}

func TestCopytruncateRetainsAppenderAndPrivateBoundedRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updater.log")
	f, err := openLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Repeat("x", 3*logLimit)); err != nil {
		t.Fatal(err)
	}
	if err := rotateLog(f, path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("after rotation\n"); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(path)
	prior, _ := os.ReadFile(path + ".1")
	if string(current) != "after rotation\n" || len(prior) != logLimit {
		t.Fatal("copytruncate did not preserve active append inode")
	}
	for _, name := range []string{path, path + ".1"} {
		info, _ := os.Stat(name)
		if info.Mode().Perm() != 0600 {
			t.Fatal("log mode differs")
		}
	}
}
