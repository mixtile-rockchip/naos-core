package hawkbit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

func assertCheckFailure(t *testing.T, result CheckResult, err error, code string, status int, secret string) {
	t.Helper()
	var checkError *CheckError
	if result.Valid || !errors.As(err, &checkError) || result.ErrorCode != code || checkError.Code != code || result.HTTPStatus != status {
		t.Fatalf("wrong check failure: %+v %v", result, err)
	}
	encoded, _ := json.Marshal(result)
	if secret != "" && (strings.Contains(string(encoded), secret) || strings.Contains(err.Error(), secret)) {
		t.Fatal("token/response/URL secret leaked")
	}
}

func TestCheckDisabledCredentialsAndStatusCodes(t *testing.T) {
	var gotToken atomic.Value
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		gotToken.Store(token)
		if r.URL.Path != "/DEFAULT/controller/v1/fixture-01" {
			t.Error("wrong DDI controller path")
		}
		if token != "TargetToken fixture-secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "private-response")
			return
		}
		io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:07"}},"_links":{"deploymentBase":{"href":"https://unused.invalid/action"}}}`)
	}))
	defer s.Close()
	cfg := fixtureConfig(t, s.URL)
	cfg.Enabled, cfg.DownloadPath, cfg.PollInterval = false, "", 0
	result, err := Check(context.Background(), cfg)
	if err != nil || !result.Valid || result.HTTPStatus != 200 || result.PollingSleep != "7s" || result.ServerURL != s.URL || result.ControllerID != cfg.ControllerID {
		t.Fatalf("disabled check failed: %+v %v", result, err)
	}
	cfg.Token = "valid-format-wrong-token"
	result, err = Check(context.Background(), cfg)
	assertCheckFailure(t, result, err, "UNAUTHORIZED", 401, cfg.Token)
	if gotToken.Load() != "TargetToken "+cfg.Token {
		t.Fatal("wrong but valid-format token was not actually sent")
	}
	for _, status := range []int{http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status); io.WriteString(w, cfg.Token) }))
			defer server.Close()
			cfg.ServerURL = server.URL
			result, err := Check(context.Background(), cfg)
			code := "HTTP"
			if status == 403 {
				code = "FORBIDDEN"
			}
			assertCheckFailure(t, result, err, code, status, cfg.Token)
		})
	}
}

func TestCheckConfigurationResponseRedirectAndTLS(t *testing.T) {
	result, err := Check(context.Background(), config.HawkbitConfig{})
	assertCheckFailure(t, result, err, "CONFIGURATION", 0, "")
	cfg := fixtureConfig(t, "https://user:url-secret@example.invalid/?token=url-secret")
	result, err = Check(context.Background(), cfg)
	assertCheckFailure(t, result, err, "CONFIGURATION", 0, "url-secret")
	if result.ServerURL != "" {
		t.Fatal("invalid credential-bearing URL exposed")
	}
	for name, body := range map[string]string{"html": "private-response", "oversize": strings.Repeat("x", maxResponse+1), "missing-ddi": `{}`, "extra-json": `{"config":{"polling":{"sleep":"00:00:01"}}}{}`} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }))
			defer server.Close()
			result, err := Check(context.Background(), fixtureConfig(t, server.URL))
			assertCheckFailure(t, result, err, "RESPONSE", 200, "private-response")
		})
	}
	var followed atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { followed.Add(1) }))
	defer foreign.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/?token=redirect-secret", 302)
	}))
	defer redirect.Close()
	result, err = Check(context.Background(), fixtureConfig(t, redirect.URL))
	assertCheckFailure(t, result, err, "REDIRECT", 302, "redirect-secret")
	if followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer tlsServer.Close()
	result, err = Check(context.Background(), fixtureConfig(t, tlsServer.URL))
	assertCheckFailure(t, result, err, "TLS", 0, "")
}

func TestCheckTimeoutCanceledAndNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result, err := Check(ctx, cfg)
	assertCheckFailure(t, result, err, "TIMEOUT", 0, cfg.Token)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	result, err = Check(canceled, cfg)
	assertCheckFailure(t, result, err, "CANCELED", 0, cfg.Token)
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	origin := closed.URL
	closed.Close()
	result, err = Check(context.Background(), fixtureConfig(t, origin))
	assertCheckFailure(t, result, err, "NETWORK", 0, "")
}
