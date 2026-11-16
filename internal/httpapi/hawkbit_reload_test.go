package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/server"
)

func startHawkbitReloadServer(t *testing.T, reload func(context.Context, string) (bool, bool, error)) (*http.Client, string) {
	t.Helper()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "core.sock")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		stopped <- server.Run(ctx, config.Config{HTTPEnabled: true, HTTPListen: address, Socket: socket}, New(Services{HawkbitReload: reload}))
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		cancel()
		select {
		case err := <-stopped:
			if err != nil {
				t.Errorf("Core listener shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Core listeners did not shut down")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://unix/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return client, "http://" + address
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Core Unix listener did not become ready")
	return nil, ""
}

func postHawkbitReload(t *testing.T, client *http.Client, url, body, contentType string) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url+"/v1/hawkbit/reload", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", contentType)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(data)
}

func TestHawkbitReloadRequiresActualUnixConnection(t *testing.T) {
	var calls atomic.Int32
	local, tcp := startHawkbitReloadServer(t, func(_ context.Context, path string) (bool, bool, error) {
		calls.Add(1)
		if path != "/tmp/device.ini" {
			t.Errorf("unexpected config path %q", path)
		}
		return true, false, nil
	})
	status, body := postHawkbitReload(t, local, "http://unix", `{"config_path":"/tmp/./device.ini"}`, "application/json")
	if status != http.StatusOK || strings.TrimSpace(body) != `{"applied":true,"pending":false}` {
		t.Fatalf("Unix reload: status=%d body=%s", status, body)
	}
	request, err := http.NewRequest(http.MethodPost, tcp+"/v1/hawkbit/reload", strings.NewReader(`{"config_path":"/tmp/device.ini"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "unix"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "unix")
	request.Header.Set("X-Forwarded-Proto", "unix")
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(data), `"UNIX_REQUIRED"`) || calls.Load() != 1 {
		t.Fatalf("TCP bypassed Unix restriction: status=%d calls=%d body=%s", response.StatusCode, calls.Load(), data)
	}
}

func TestHawkbitReloadResultContractAndErrorPrivacy(t *testing.T) {
	for _, test := range []struct {
		name             string
		applied, pending bool
		err              error
		status           int
	}{
		{"applied", true, false, nil, http.StatusOK},
		{"pending", false, true, nil, http.StatusAccepted},
		{"failed", false, false, errors.New("private-token /private/config.ini"), http.StatusServiceUnavailable},
		{"neither", false, false, nil, http.StatusServiceUnavailable},
		{"both", true, true, nil, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			local, _ := startHawkbitReloadServer(t, func(context.Context, string) (bool, bool, error) {
				return test.applied, test.pending, test.err
			})
			status, body := postHawkbitReload(t, local, "http://unix", `{"config_path":"/private/config.ini"}`, "application/json")
			if status != test.status || strings.Contains(body, "private") {
				t.Fatalf("unexpected response or disclosed config: status=%d body=%s", status, body)
			}
			if status >= 400 {
				if !strings.Contains(body, `"APPLY_FAILED"`) {
					t.Fatal("reload error lacks APPLY_FAILED")
				}
				return
			}
			var result map[string]bool
			if err := json.Unmarshal([]byte(body), &result); err != nil || len(result) != 2 || result["applied"] != test.applied || result["pending"] != test.pending {
				t.Fatalf("unexpected reload payload: %s (%v)", body, err)
			}
		})
	}
	local, _ := startHawkbitReloadServer(t, nil)
	status, body := postHawkbitReload(t, local, "http://unix", `{"config_path":"/private/config.ini"}`, "application/json")
	if status != http.StatusServiceUnavailable || !strings.Contains(body, `"APPLY_FAILED"`) || strings.Contains(body, "private") {
		t.Fatalf("unconfigured reload response: status=%d body=%s", status, body)
	}
}

func TestHawkbitReloadRejectsInvalidInputWithoutDisclosure(t *testing.T) {
	var calls atomic.Int32
	local, _ := startHawkbitReloadServer(t, func(context.Context, string) (bool, bool, error) {
		calls.Add(1)
		return true, false, nil
	})
	for _, test := range []struct {
		name, contentType, body string
	}{
		{"content-type", "text/plain", `{"config_path":"/private-token"}`},
		{"malformed", "application/json", `{"config_path":"/private-token"`},
		{"unknown", "application/json", `{"config_path":"/tmp/device.ini","private-token":true}`},
		{"multiple", "application/json", `{"config_path":"/private-token"}{}`},
		{"missing", "application/json", `{}`},
		{"relative", "application/json", `{"config_path":"private-token"}`},
		{"nul", "application/json", `{"config_path":"/private-token\u0000"}`},
		{"oversized", "application/json", `{"config_path":"/` + strings.Repeat("private-token", 400) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, body := postHawkbitReload(t, local, "http://unix", test.body, test.contentType)
			if status != http.StatusBadRequest || strings.Contains(body, "private-token") || calls.Load() != 0 {
				t.Fatalf("invalid request reached callback or disclosed input: status=%d calls=%d body=%s", status, calls.Load(), body)
			}
		})
	}
}
