package hawkbit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startManager(t *testing.T, manager *Manager) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = manager.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if runErr != nil {
				t.Errorf("manager stopped: %v", runErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("manager shutdown timed out")
		}
	})
	eventually(t, time.Second, func() bool {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return manager.running
	})
	return cancel, done
}

func managerRunner(manager *Manager) *Runner {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.current
}

func TestManagerEnablesDisabledRunnerAndAppliesIdleReload(t *testing.T) {
	var lastPath atomic.Value
	var lastAuth atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		lastPath.Store(r.URL.Path)
		lastAuth.Store(r.Header.Get("Authorization"))
		io.WriteString(w, `{"config":{"polling":{"sleep":"01:00:00"}}}`)
	}))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	cfg.PollInterval = time.Hour
	cfg.Enabled = false
	hooks := noopHooks()
	hooks.BeginExternal = func(context.Context, ExternalRequest) (string, error) {
		return "", errors.New("fixture operation is busy")
	}
	manager, err := NewManager(cfg, hooks, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.current.options.directory = filepath.Join(t.TempDir(), "runtime")
	manager.current.options.updater = filepath.Join(t.TempDir(), "unused-updater")
	if applied, pending, err := manager.Reload(context.Background(), cfg); applied || pending || !errors.Is(err, ErrManagerNotRunning) {
		t.Fatal("reload before Run was accepted")
	}
	cancel, done := startManager(t, manager)
	select {
	case <-done:
		t.Fatal("disabled configuration stopped the manager")
	default:
	}
	if err := manager.Run(context.Background()); err == nil {
		t.Fatal("duplicate Run was accepted")
	}
	cfg.Enabled = true
	if applied, pending, err := manager.Reload(context.Background(), cfg); !applied || pending || err != nil {
		t.Fatalf("enable: applied=%v pending=%v err=%v", applied, pending, err)
	}
	eventually(t, time.Second, func() bool {
		status := manager.Snapshot()
		return status.Heartbeat.HTTPStatus == 200 && status.Updater.Phase == "deferred" && !status.Updater.NextRun.IsZero()
	})
	previous := managerRunner(manager)
	invalid := cfg
	invalid.ServerURL = "http://invalid/path"
	if applied, pending, err := manager.Reload(context.Background(), invalid); applied || pending || err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if managerRunner(manager) != previous || previous.draining {
		t.Fatal("failed validation touched the current runner")
	}
	requestCtx, requestCancel := context.WithCancel(context.Background())
	requestCancel()
	if applied, pending, err := manager.Reload(requestCtx, cfg); applied || pending || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request was applied")
	}
	cfg.ControllerID = "fixture-new"
	cfg.Token = "fixture-reloaded-token"
	if applied, pending, err := manager.Reload(context.Background(), cfg); !applied || pending || err != nil {
		t.Fatalf("idle reload: applied=%v pending=%v err=%v", applied, pending, err)
	}
	eventually(t, time.Second, func() bool {
		return lastPath.Load() == "/DEFAULT/controller/v1/fixture-new" && lastAuth.Load() == "TargetToken fixture-reloaded-token" && manager.Snapshot().Heartbeat.HTTPStatus == 200
	})
	if managerRunner(manager).cfg != cfg || previous.cfg.ControllerID == cfg.ControllerID {
		t.Fatal("runner configuration was mutated instead of replaced")
	}
	previous.mu.Lock()
	stillRunning := previous.running
	previous.mu.Unlock()
	if stillRunning {
		t.Fatal("old runner still runs after replacement")
	}
	cancel()
	<-done
	if applied, pending, err := manager.Reload(context.Background(), cfg); applied || pending || !errors.Is(err, ErrManagerNotRunning) {
		t.Fatal("stopped manager accepted a reload")
	}
}

func TestManagerPendingReloadPreservesUpdaterCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"config":{"polling":{"sleep":"01:00:00"}}}`)
	}))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	cfg.Timeout, cfg.PollInterval = 5*time.Second, time.Hour
	h := &hookFixture{}
	hooks := h.hooks()
	end := hooks.EndExternal
	finishing, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseEnd := func() { once.Do(func() { close(release) }) }
	hooks.EndExternal = func(ctx context.Context, id string, code int, runErr error) error {
		close(finishing)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return end(ctx, id, code, runErr)
		}
	}
	manager, err := NewManager(cfg, hooks, nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "runtime")
	manager.current.options = setupRunner(t, cfg, hooks, directory, "250ms").options
	startManager(t, manager)
	t.Cleanup(releaseEnd)
	eventually(t, 3*time.Second, func() bool { return manager.Snapshot().Updater.Phase == "running" })
	before, err := os.ReadFile(configPath(directory))
	if err != nil {
		t.Fatal(err)
	}
	disabled := cfg
	disabled.Enabled = false
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	applied, pending, err := manager.Reload(requestCtx, disabled)
	cancelRequest()
	if applied || !pending || err != nil {
		t.Fatalf("active reload: applied=%v pending=%v err=%v", applied, pending, err)
	}
	if applied, pending, err := manager.Reload(context.Background(), cfg); applied || pending || !errors.Is(err, ErrReloadBusy) {
		t.Fatal("another reload replaced the pending configuration")
	}
	select {
	case <-finishing:
	case <-time.After(3 * time.Second):
		t.Fatal("updater was detached instead of reaching EndExternal")
	}
	if !manager.Snapshot().Enabled || managerRunner(manager).cfg != cfg {
		t.Fatal("configuration changed before EndExternal completed")
	}
	after, _ := os.ReadFile(configPath(directory))
	if !bytes.Equal(before, after) {
		t.Fatal("reload rewrote an updater's active configuration")
	}
	releaseEnd()
	eventually(t, time.Second, func() bool { return !manager.Snapshot().Enabled })
	h.mu.Lock()
	ends, tasks := h.ends, len(h.tasks)
	h.mu.Unlock()
	if ends != 1 || tasks != 1 || managerRunner(manager).cfg != disabled {
		t.Fatal("pending configuration was not applied after one complete updater run")
	}
	starts, _ := os.ReadFile(filepath.Join(directory, "starts"))
	if string(starts) != "start\n" {
		t.Fatal("drain allowed another updater to start")
	}
}

func TestManagerShutdownDetachesAndNextManagerSkipsUpdater(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"config":{"polling":{"sleep":"01:00:00"}}}`)
	}))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	cfg.PollInterval = time.Hour
	h := &hookFixture{}
	manager, err := NewManager(cfg, h.hooks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "runtime")
	manager.current.options = setupRunner(t, cfg, h.hooks(), directory, "1200ms").options
	cancel, done := startManager(t, manager)
	eventually(t, 3*time.Second, func() bool { return manager.Snapshot().Updater.Phase == "running" })
	pid := manager.Snapshot().Updater.PID
	t.Cleanup(func() {
		eventually(t, 5*time.Second, func() bool { _, err := processIdentity(pid); return err != nil })
	})
	before, _ := os.ReadFile(configPath(directory))
	disabled := cfg
	disabled.Enabled = false
	if applied, pending, err := manager.Reload(context.Background(), disabled); applied || !pending || err != nil {
		t.Fatal("active reload was not pending")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("service shutdown waited for the updater instead of detaching")
	}
	if _, err := processIdentity(pid); err != nil {
		t.Fatal("service shutdown killed the updater")
	}
	if !manager.Snapshot().Enabled || manager.Snapshot().Updater.Phase != "detached" {
		t.Fatal("shutdown applied pending configuration or lost detached state")
	}
	next, err := NewManager(cfg, h.hooks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	next.current.options = managerRunner(manager).options
	startManager(t, next)
	eventually(t, time.Second, func() bool { return next.Snapshot().Updater.Phase == "skipped" })
	if status := next.Snapshot(); status.Updater.PID != 0 || status.Updater.TaskID != "" {
		t.Fatal("new manager adopted the old updater")
	}
	after, _ := os.ReadFile(configPath(directory))
	if !bytes.Equal(before, after) {
		t.Fatal("new manager overwrote the old updater configuration")
	}
	h.mu.Lock()
	ends, tasks := h.ends, len(h.tasks)
	h.mu.Unlock()
	if ends != 0 || tasks != 1 {
		t.Fatal("shutdown or replacement fabricated updater completion")
	}
}
