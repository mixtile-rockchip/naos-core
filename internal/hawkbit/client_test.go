package hawkbit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

func fixtureConfig(t *testing.T, server string) config.HawkbitConfig {
	t.Helper()
	return config.HawkbitConfig{Enabled: true, ServerURL: server, Tenant: "DEFAULT", ControllerID: "fixture-01", Token: "fixture-secret-token", PollInterval: time.Second, Timeout: time.Second, DownloadPath: filepath.Join(t.TempDir(), "downloads")}
}

func noopHooks() Hooks {
	return Hooks{BeginExternal: func(context.Context, ExternalRequest) (string, error) { return "fixture-task", nil }, AttachExternal: func(context.Context, string, ProcessIdentity) error { return nil }, EndExternal: func(context.Context, string, int, error) error { return nil }}
}

func TestDDIHeartbeatBoundsAuthenticationAndTLS(t *testing.T) {
	var authOK atomic.Bool
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authOK.Store(r.Header.Get("Authorization") == "TargetToken fixture-secret-token" && r.URL.Path == "/DEFAULT/controller/v1/fixture-01")
		io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:03"}},"_links":{"deploymentBase":{"href":"https://untrusted.invalid/token"}}}`)
	}))
	defer good.Close()
	cfg := fixtureConfig(t, good.URL)
	r, err := New(cfg, noopHooks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.transport.CloseIdleConnections()
	result, err := poll(context.Background(), r.client, r.origin, cfg)
	if err != nil || !authOK.Load() || result.Sleep != 3*time.Second || result.Action != "deployment" {
		t.Fatalf("unexpected heartbeat result: %+v %v", result, err)
	}
	for name, body := range map[string]string{"oversize": strings.Repeat("x", maxResponse+1), "extra-json": `{"config":{"polling":{"sleep":"00:00:01"}}}{}`, "zero-sleep": `{"config":{"polling":{"sleep":"00:00:00"}}}`, "invalid-sleep": `{"config":{"polling":{"sleep":"00:61:01"}}}`} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
			defer s.Close()
			c := fixtureConfig(t, s.URL)
			runner, _ := New(c, noopHooks(), nil)
			defer runner.transport.CloseIdleConnections()
			if _, err := poll(context.Background(), runner.client, runner.origin, c); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	var leaked atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer foreign.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { http.Redirect(w, req, foreign.URL, http.StatusFound) }))
	defer redirect.Close()
	cfg = fixtureConfig(t, redirect.URL)
	r, _ = New(cfg, noopHooks(), nil)
	defer r.transport.CloseIdleConnections()
	if _, err := poll(context.Background(), r.client, r.origin, cfg); err == nil || leaked.Load() != 0 {
		t.Fatal("redirect followed or accepted")
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer tlsServer.Close()
	cfg = fixtureConfig(t, tlsServer.URL)
	r, _ = New(cfg, noopHooks(), nil)
	defer r.transport.CloseIdleConnections()
	if _, err := poll(context.Background(), r.client, r.origin, cfg); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestHeartbeatTimeoutAndPrivateAtomicINI(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	cfg := fixtureConfig(t, s.URL)
	r, err := New(cfg, noopHooks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.transport.CloseIdleConnections()
	started := time.Now()
	if _, err := poll(context.Background(), r.client, r.origin, cfg); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("request deadline not enforced")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "hawkbit.conf")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, ini(cfg, r.origin)); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	data, _ := readPrivate(path, 8192)
	if info.Mode().Perm() != 0600 || !strings.Contains(string(data), "auth_token="+cfg.Token+"\n") || !strings.Contains(string(data), "[device]\nsource=naos-core\n") || !strings.Contains(string(data), "stream_bundle=false\n") || !strings.Contains(string(data), "ssl_verify=true\n") || !strings.Contains(string(data), "post_update_reboot=false\n") {
		t.Fatal("private updater INI policy differs")
	}
	for _, bad := range []string{"https://user:secret@example.com", "https://example.com/prefix", "https://example.com?token=secret"} {
		cfg.ServerURL = bad
		if _, err := validate(cfg); err == nil {
			t.Fatal("unsafe server origin accepted")
		}
	}
}

func TestDisabledIsIdleWithoutFilesystemOrNetwork(t *testing.T) {
	r, err := New(config.HawkbitConfig{}, Hooks{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.options.directory = filepath.Join(t.TempDir(), "not-created")
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.options.directory); !os.IsNotExist(err) {
		t.Fatal("disabled runner touched runtime directory")
	}
	if r.Snapshot().State != "disabled" {
		t.Fatal("disabled runner reported an active lifecycle")
	}
	data, _ := json.Marshal(r.Snapshot())
	if strings.Contains(string(data), "secret") {
		t.Fatal("credential leaked")
	}
}

func TestStartupFailureIsVisibleInSnapshot(t *testing.T) {
	for _, cause := range []string{"runtime", "download", "lock"} {
		t.Run(cause, func(t *testing.T) {
			cfg := fixtureConfig(t, "http://127.0.0.1:1")
			r, err := New(cfg, noopHooks(), nil)
			if err != nil {
				t.Fatal(err)
			}
			r.options.directory = filepath.Join(t.TempDir(), "runtime")
			switch cause {
			case "runtime":
				err = os.WriteFile(r.options.directory, []byte("occupied"), 0600)
			case "download":
				err = os.MkdirAll(cfg.DownloadPath, 0755)
				if err == nil {
					err = os.Chmod(cfg.DownloadPath, 0755)
				}
			case "lock":
				if err = privateDir(r.options.directory); err == nil {
					var f *os.File
					f, err = lockFile(filepath.Join(r.options.directory, "hawkbit-controller.lock"))
					if err == nil {
						t.Cleanup(func() { _ = f.Close() })
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := r.Run(ctx); err == nil {
				t.Fatal("invalid startup unexpectedly succeeded")
			}
			if s := r.Snapshot(); !s.Enabled || s.State != "failed" {
				t.Fatalf("startup failure was indistinguishable from idle: enabled=%v state=%s", s.Enabled, s.State)
			}
		})
	}
}

func TestBackoffAndPollingSleep(t *testing.T) {
	if backoff(time.Second, 3) != 4*time.Second || backoff(4*time.Hour, 1) != 4*time.Hour || backoff(12*time.Hour, 8) != 24*time.Hour {
		t.Fatal("failure backoff differs")
	}
	for _, v := range []string{"", "1:00:00", "00:00:00", "24:00:00", "00:60:00", "-1:00:01"} {
		if _, err := pollingSleep(v); err == nil {
			t.Fatalf("accepted invalid sleep %q", v)
		}
	}
}
