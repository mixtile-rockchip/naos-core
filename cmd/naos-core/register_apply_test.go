package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
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

const registrationApplyToken = "explicit-register-apply-test-token"

type registrationApplyReply struct {
	registrationReply
	Applied        bool `json:"applied"`
	Pending        bool `json:"pending"`
	ServiceRunning bool `json:"service_running"`
}

func registrationApplyConfig(t *testing.T) (path, socket string, original []byte) {
	t.Helper()
	path, _, original = registrationINI(t)
	// Keep the Unix path short even for long test and subtest names.
	dir, err := os.MkdirTemp("", "register-apply-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket = filepath.Join(dir, "core.sock")
	original = bytes.ReplaceAll(original, []byte("/run/naos/register-test-no-core.sock"), []byte(socket))
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	return path, socket, original
}

func registrationApplyServer(t *testing.T, socket string, handler http.Handler) {
	t.Helper()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fake Core server did not stop")
		}
	})
}

func registrationApplyDDI(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	requests := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "GatewayToken "+registrationApplyToken {
			t.Error("registration did not use the explicit gateway credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:30"}}}`)
		} else {
			_, _ = io.WriteString(w, registrationApplyToken+":private-registration-response")
		}
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func registrationApplyJSON(t *testing.T, out, stderr string) registrationApplyReply {
	t.Helper()
	for _, secret := range []string{registrationApplyToken, "previous-ini-token", "private-registration-response", "private-Core-response"} {
		if strings.Contains(out+stderr, secret) {
			t.Fatal("registration output disclosed credentials or a private response")
		}
	}
	var result registrationApplyReply
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("registration did not return one JSON result: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"registered", "saved", "applied", "pending", "service_running"} {
		if _, ok := fields[field]; !ok {
			t.Errorf("registration omitted %s", field)
		}
	}
	return result
}

func TestManualRegisterAppliesToRunningCoreWithCustomINI(t *testing.T) {
	for _, fixture := range []struct {
		name, body       string
		status           int
		applied, pending bool
	}{
		{"applied", `{"applied":true,"pending":false}`, http.StatusOK, true, false},
		{"pending", `{"applied":false,"pending":true}`, http.StatusAccepted, false, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ddi, ddiRequests := registrationApplyDDI(t, http.StatusOK)
			path, socket, _ := registrationApplyConfig(t)
			var reloadRequests atomic.Int32
			registrationApplyServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reloadRequests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/v1/hawkbit/reload" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("registration did not send the Unix reload protocol")
				}
				var request struct {
					ConfigPath string `json:"config_path"`
				}
				decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&request); err != nil || request.ConfigPath != path {
					t.Error("reload did not identify the selected INI by its absolute path")
				}
				cfg, err := config.Load(path)
				if err != nil || cfg.Hawkbit.ServerURL != ddi.URL || cfg.Hawkbit.Token != registrationApplyToken || cfg.Hawkbit.ControllerID == "PREVIOUS_DEVICE_ID" || !cfg.Hawkbit.Enabled {
					t.Error("Core was notified before the enabled registered profile was persisted")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(fixture.status)
				_, _ = io.WriteString(w, fixture.body)
			}))
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			relative, err := filepath.Rel(cwd, path)
			if err != nil {
				t.Fatal(err)
			}
			code, out, stderr := helpRun("hawkbit", "register", "--config", relative, "--server", ddi.URL, "--tenant", "REGISTER_TENANT", "--token", registrationApplyToken)
			result := registrationApplyJSON(t, out, stderr)
			if code != 0 || !result.Registered || !result.Saved || !result.ServiceRunning || result.Applied != fixture.applied || result.Pending != fixture.pending || result.ErrorCode != "" {
				t.Fatalf("running-Core registration: code=%d result=%+v", code, result)
			}
			if ddiRequests.Load() != 1 || reloadRequests.Load() != 1 {
				t.Fatalf("unexpected requests: DDI=%d reload=%d", ddiRequests.Load(), reloadRequests.Load())
			}
		})
	}
}

func TestManualRegisterSavesWhenCoreIsNotRunning(t *testing.T) {
	for _, name := range []string{"missing socket", "stale socket"} {
		t.Run(name, func(t *testing.T) {
			ddi, requests := registrationApplyDDI(t, http.StatusOK)
			path, socket, _ := registrationApplyConfig(t)
			if name == "stale socket" {
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				listener.SetUnlinkOnClose(false)
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", ddi.URL, "--tenant", "REGISTER_TENANT", "--token", registrationApplyToken)
			result := registrationApplyJSON(t, out, stderr)
			if code != 0 || !result.Registered || !result.Saved || result.Applied || result.Pending || result.ServiceRunning || result.ErrorCode != "" || requests.Load() != 1 {
				t.Fatalf("offline-Core registration: code=%d result=%+v requests=%d", code, result, requests.Load())
			}
			cfg, err := config.Load(path)
			if err != nil || cfg.Hawkbit.Token != registrationApplyToken || !cfg.Hawkbit.Enabled {
				t.Fatal("offline registration did not persist its enabled gateway profile")
			}
		})
	}
}

func TestManualRegisterRetainsSuccessWhenCoreApplyFails(t *testing.T) {
	for _, fixture := range []struct {
		name, body string
		status     int
	}{
		{"HTTP failure", "private-Core-response:" + registrationApplyToken, http.StatusServiceUnavailable},
		{"invalid JSON", "private-Core-response:" + registrationApplyToken, http.StatusOK},
		{"no apply result", `{}`, http.StatusOK},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ddi, requests := registrationApplyDDI(t, http.StatusOK)
			path, socket, _ := registrationApplyConfig(t)
			var reloadRequests atomic.Int32
			registrationApplyServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reloadRequests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(fixture.status)
				_, _ = io.WriteString(w, fixture.body)
			}))
			code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", ddi.URL, "--tenant", "REGISTER_TENANT", "--token", registrationApplyToken)
			result := registrationApplyJSON(t, out, stderr)
			if code != 1 || !result.Registered || !result.Saved || result.Applied || result.Pending || !result.ServiceRunning || result.ErrorCode != "APPLY" {
				t.Fatalf("apply failure lost registration or persistence success: code=%d result=%+v", code, result)
			}
			if requests.Load() != 1 || reloadRequests.Load() != 1 {
				t.Fatalf("unexpected requests: DDI=%d reload=%d", requests.Load(), reloadRequests.Load())
			}
			cfg, err := config.Load(path)
			if err != nil || cfg.Hawkbit.Token != registrationApplyToken || cfg.Hawkbit.ControllerID != result.ControllerID {
				t.Fatal("apply failure removed the saved registration")
			}
		})
	}
}

func TestManualRegisterFailureDoesNotNotifyCore(t *testing.T) {
	ddi, requests := registrationApplyDDI(t, http.StatusUnauthorized)
	path, socket, original := registrationApplyConfig(t)
	var reloadRequests atomic.Int32
	registrationApplyServer(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reloadRequests.Add(1)
		_, _ = io.WriteString(w, `{"applied":true,"pending":false}`)
	}))
	code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", ddi.URL, "--tenant", "REGISTER_TENANT", "--token", registrationApplyToken)
	result := registrationApplyJSON(t, out, stderr)
	if code != 1 || result.Registered || result.Saved || result.Applied || result.Pending || result.ServiceRunning || result.ErrorCode != "UNAUTHORIZED" || requests.Load() != 1 || reloadRequests.Load() != 0 {
		t.Fatalf("failed registration contacted Core: code=%d result=%+v DDI=%d reload=%d", code, result, requests.Load(), reloadRequests.Load())
	}
	updated, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, updated) {
		t.Fatal("failed registration changed the INI")
	}
}
