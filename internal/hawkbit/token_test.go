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
)

func TestTokenTypeHeaderCheckAndUpdaterINIStayConsistent(t *testing.T) {
	for _, mode := range []string{"", "target", "gateway"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			scheme, key, other := "TargetToken", "auth_token", "gateway_token"
			if mode == "gateway" {
				scheme, key, other = "GatewayToken", "gateway_token", "auth_token"
			}
			var authenticated atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authenticated.Store(r.Header.Get("Authorization") == scheme+" fixture-secret-token")
				io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:05"}}}`)
			}))
			defer server.Close()
			cfg := fixtureConfig(t, server.URL)
			cfg.TokenType = mode
			runner, err := New(cfg, noopHooks(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer runner.transport.CloseIdleConnections()
			text := string(ini(cfg, runner.origin))
			if !strings.Contains(text, "\n"+key+"="+cfg.Token+"\n") || strings.Contains(text, "\n"+other+"=") {
				t.Fatal("updater INI auth mode differs or includes both tokens")
			}
			cfg.Enabled = false
			result, err := Check(context.Background(), cfg)
			if err != nil || !result.Valid || !authenticated.Load() {
				t.Fatalf("check/header auth mode differs: %+v %v", result, err)
			}
			public, _ := json.Marshal(result)
			if strings.Contains(string(public), cfg.Token) {
				t.Fatal("check leaked token")
			}
		})
	}
}

func TestUnknownTokenTypeIsRejectedWithoutRequestOrValueLeak(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	cfg.TokenType = "unknown-" + cfg.Token
	if _, err := New(cfg, noopHooks(), nil); err == nil || strings.Contains(err.Error(), cfg.Token) {
		t.Fatal("unknown token type accepted or leaked")
	}
	result, err := Check(context.Background(), cfg)
	assertCheckFailure(t, result, err, "CONFIGURATION", 0, cfg.Token)
	if calls.Load() != 0 {
		t.Fatal("invalid token type sent a request")
	}
}

func TestRecentLogsRedactBothOldINITokenKeys(t *testing.T) {
	for _, key := range []string{"auth_token", "gateway_token"} {
		t.Run(key, func(t *testing.T) {
			cfg := fixtureConfig(t, "http://127.0.0.1:1")
			cfg.Token = "current-secret-token"
			runner, err := New(cfg, noopHooks(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer runner.transport.CloseIdleConnections()
			runner.options.directory = t.TempDir()
			old := "old-mode-secret-token"
			if err := atomicWrite(configPath(runner.options.directory), []byte("[client]\n"+key+"="+old+"\n")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(runner.options.directory, "hawkbit-updater.log"), []byte(old+"\n"+cfg.Token+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(runner.Snapshot())
			if strings.Contains(string(encoded), old) || strings.Contains(string(encoded), cfg.Token) || !strings.Contains(string(encoded), "[redacted]") {
				t.Fatal("snapshot did not redact both active and prior INI tokens")
			}
		})
	}
}
