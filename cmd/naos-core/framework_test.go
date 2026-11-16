package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParserRejectsInvalidInputWithoutEchoingSecrets(t *testing.T) {
	const secret = "parser-secret-token-must-not-be-printed"
	unreadable := t.TempDir()
	cases := [][]string{
		{"--" + secret},
		{"--unknown=" + secret},
		{secret, "--config", unreadable},
		{"help", secret},
		{"help", "--" + secret},
		{"hawkbit", "help", "--" + secret},
		{"hawkbit", "register", "help", "--" + secret},
		{"containers", "start", "help", "--" + secret},
		{"help", "--help=" + secret},
		{"hawkbit", secret, "--config", unreadable},
		{"hawkbit", "status", "--unknown=" + secret, "--config", unreadable},
		{"hawkbit", "check", "--token", secret, "--config", unreadable},
		{"hawkbit", "register", "--token", secret, "--server", "http://invalid.example", "--tenant", "DEFAULT", "--" + secret},
		{"hawkbit", "register", "--token", secret, "--tenant", "DEFAULT"},
		{"hawkbit", "register", "--server", "http://invalid.example", "--tenant", "DEFAULT", "--token=" + secret, "extra"},
		{"containers", "start", "demo", secret, "--config", unreadable},
		{"update", "--request-id", secret, "--config", unreadable},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 2 || strings.Contains(out+stderr, secret) || strings.Contains(out+stderr, unreadable) {
				t.Fatalf("invalid arguments were accepted, read configuration, or leaked a value: code=%d", code)
			}
		})
	}
}

func TestParserInheritedConfigAndInterspersedFlagsUseCoreSocket(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "core.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	type expectedRequest struct{ method, path, bundle, requestID string }
	var expectation atomic.Pointer[expectedRequest]
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		expected := expectation.Load()
		if r.Method != expected.method || r.URL.Path != expected.path {
			t.Errorf("request=%s %s, want %s %s", r.Method, r.URL.Path, expected.method, expected.path)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/update" {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["path"] != expected.bundle || body["request_id"] != expected.requestID {
				t.Errorf("unexpected local update payload: %+v, %v", body, err)
			}
		}
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-finished }()
	cfg := filepath.Join(dir, "device.ini")
	if err := os.WriteFile(cfg, []byte("[core]\nsocket="+socket+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args                            []string
		method, path, bundle, requestID string
	}{
		{[]string{"--config", cfg, "containers"}, "GET", "/v1/containers", "", ""},
		{[]string{"containers", "list", "--config", cfg}, "GET", "/v1/containers", "", ""},
		{[]string{"--config", cfg, "containers", "start", "demo"}, "POST", "/v1/containers/demo/start", "", ""},
		{[]string{"containers", "--config", cfg, "start", "demo"}, "POST", "/v1/containers/demo/start", "", ""},
		{[]string{"containers", "start", "--config", cfg, "demo"}, "POST", "/v1/containers/demo/start", "", ""},
		{[]string{"containers", "stop", "demo", "--config", cfg}, "POST", "/v1/containers/demo/stop", "", ""},
		{[]string{"containers", "restart", "demo", "--config=" + cfg}, "POST", "/v1/containers/demo/restart", "", ""},
		{[]string{"-config=" + cfg, "containers", "start", "demo"}, "POST", "/v1/containers/demo/start", "", ""},
		{[]string{"containers", "stop", "demo", "-config", cfg}, "POST", "/v1/containers/demo/stop", "", ""},
		{[]string{"containers", "start", "--config", cfg, "--", "--help"}, "POST", "/v1/containers/--help/start", "", ""},
		{[]string{"containers", "stop", "--config", cfg, "--", "help"}, "POST", "/v1/containers/help/stop", "", ""},
		{[]string{"containers", "restart", "--config", cfg, "--", "--config"}, "POST", "/v1/containers/--config/restart", "", ""},
		{[]string{"update", "/userdata/update.raucb", "--request-id", "interspersed-request", "--config", cfg}, "POST", "/v1/update", "/userdata/update.raucb", "interspersed-request"},
		{[]string{"--config", cfg, "update", "--request-id=global-request", "/userdata/update.raucb"}, "POST", "/v1/update", "/userdata/update.raucb", "global-request"},
		{[]string{"update", "--config", cfg, "--", "--bundle-name.raucb"}, "POST", "/v1/update", "--bundle-name.raucb", ""},
		{[]string{"update", "-config=" + cfg, "-request-id=single-dash-request", "local.raucb"}, "POST", "/v1/update", "local.raucb", "single-dash-request"},
		{[]string{"update", "--config", cfg, "--request-id=literal-help-bundle", "--", "--help"}, "POST", "/v1/update", "--help", "literal-help-bundle"},
		{[]string{"update", "--config", cfg}, "GET", "/v1/update", "", ""},
		{[]string{"tasks", "--config", cfg}, "GET", "/v1/update-tasks", "", ""},
		{[]string{"task", "task-id", "--config", cfg}, "GET", "/v1/update-tasks/task-id", "", ""},
		{[]string{"task", "--config", cfg, "--", "--help"}, "GET", "/v1/update-tasks/--help", "", ""},
		{[]string{"reboot", "--config", cfg}, "POST", "/v1/reboot", "", ""},
		{[]string{"recovery", "--config", cfg}, "POST", "/v1/recovery", "", ""},
		{[]string{"--config", cfg, "hawkbit", "status"}, "GET", "/v1/hawkbit", "", ""},
		{[]string{"hawkbit", "--config", cfg, "status"}, "GET", "/v1/hawkbit", "", ""},
		{[]string{"hawkbit", "status", "--config", cfg}, "GET", "/v1/hawkbit", "", ""},
	}
	for i, fixture := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			expectation.Store(&expectedRequest{fixture.method, fixture.path, fixture.bundle, fixture.requestID})
			before := requests.Load()
			code, out, stderr := helpRun(fixture.args...)
			if code != 0 || stderr != "" || !strings.Contains(out, `"status":"ok"`) || requests.Load() != before+1 {
				t.Fatalf("parsed command did not make exactly one expected API call: code=%d out=%s stderr=%s", code, out, stderr)
			}
		})
	}
}

func TestParserLeafHelpDoesNotReadConfigOrExposeFlagValues(t *testing.T) {
	const secret = "help-supplied-token-must-stay-private"
	unreadable := t.TempDir()
	cases := [][]string{
		{"--config", unreadable, "--help"},
		{"containers", "list", "--config", unreadable, "--help"},
		{"containers", "start", "--config", unreadable, "--help"},
		{"containers", "stop", "--config", unreadable, "--help"},
		{"containers", "restart", "--config", unreadable, "--help"},
		{"hawkbit", "status", "--config", unreadable, "--help"},
		{"hawkbit", "check", "--config", unreadable, "--help"},
		{"hawkbit", "register", "--token", secret, "--config", unreadable, "--help"},
		{"hawkbit", "help", "register", "--config", unreadable},
		{"containers", "help", "start", "--config", unreadable},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 0 || stderr != "" || !strings.Contains(out, "--config") || !strings.Contains(out, "USAGE:") || strings.Contains(out+stderr, secret) || strings.Contains(out+stderr, unreadable) {
				t.Fatalf("help read configuration, omitted inherited config, or exposed a flag value: code=%d", code)
			}
		})
	}
}

func TestParserHelpAliasesAndBooleanFlagValues(t *testing.T) {
	unreadable := t.TempDir()
	cases := []struct {
		args    []string
		purpose string
	}{
		{[]string{"h"}, "Manage the NAOS device"},
		{[]string{"h", "containers"}, "container"},
		{[]string{"containers", "h", "start"}, "start"},
		{[]string{"containers", "start", "h"}, "start"},
		{[]string{"hawkbit", "h", "register"}, "--token"},
		{[]string{"hawkbit", "register", "h"}, "--token"},
		{[]string{"hawkbit", "register", "--help=true"}, "--token"},
		{[]string{"containers", "start", "-h=true"}, "start"},
	}
	for i, fixture := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			args := append([]string{"--config", unreadable}, fixture.args...)
			code, out, stderr := helpRun(args...)
			if code != 0 || stderr != "" || !strings.Contains(out, "USAGE:") || !strings.Contains(out, fixture.purpose) || strings.Contains(out, unreadable) {
				t.Fatalf("help alias did not render safely: code=%d out=%s stderr=%s", code, out, stderr)
			}
		})
	}
}

func TestParserRejectsLocalFlagsAndMalformedCommandsBeforeAnyRequest(t *testing.T) {
	const secret = "invalid-arguments-secret-must-not-be-printed"
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}},"status":"ok"}`))
	})
	ddi := httptest.NewServer(handler)
	defer ddi.Close()
	dir := t.TempDir()
	socket := filepath.Join(dir, "core.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-finished }()
	cfg := filepath.Join(dir, "device.ini")
	original := []byte("[core]\nsocket=" + socket + "\n[hawkbit]\ncontroller_id=cli-parser-no-request\n")
	if err := os.WriteFile(cfg, original, 0600); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"--request-id=" + secret, "update", "local.raucb"},
		{"--server=" + ddi.URL, "hawkbit", "register"},
		{"containers", "list", "extra"},
		{"containers", "start", "demo", "--request-id=" + secret},
		{"task", "task-id", "--token=" + secret},
		{"reboot", "--server=" + ddi.URL},
		{"hawkbit", "--token=" + secret},
		{"hawkbit", "status", "--request-id=" + secret},
		{"hawkbit", "register", "--server", ddi.URL, "--tenant", "DEFAULT", "--token", secret, "--unknown"},
		{"hawkbit", "register", "--server", ddi.URL, "--tenant", "DEFAULT", "--token", secret, "unexpected"},
		{"task", "--help=" + secret},
		{"update", "--request-id"},
		{"containers", "--config"},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			args = append([]string{"--config", cfg}, args...)
			code, out, stderr := helpRun(args...)
			if code != 2 || requests.Load() != 0 || strings.Contains(out+stderr, secret) || strings.Contains(out+stderr, cfg) || strings.Contains(out+stderr, ddi.URL) {
				t.Fatalf("invalid command made a request or leaked input: code=%d requests=%d", code, requests.Load())
			}
		})
	}
	after, err := os.ReadFile(cfg)
	if err != nil || string(after) != string(original) {
		t.Fatal("invalid CLI input modified configuration")
	}
}

func TestParserOEMDispatchesWithoutCoreAndPreservesFailureExitCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.ini")
	if err := os.WriteFile(path, []byte("[platform]\nsoc=unsupported\n[core]\nsocket=/nonexistent/cli-oem.sock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := helpRun("oem", "--config", path)
	if code != 1 || out != "" || !strings.Contains(stderr, "OEM is not supported") || strings.Contains(stderr, "USAGE:") || strings.Contains(stderr, "cli-oem.sock") {
		t.Fatalf("OEM command did not preserve the direct read/error behavior: code=%d out=%s stderr=%s", code, out, stderr)
	}
}

func TestParserPreservesCoreHTTPFailureResponseAndExitCode(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "core.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	const response = "{\"error\":\"fixture unavailable\"}\n"
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/update-tasks" {
			t.Errorf("unexpected command request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(response))
	})}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-finished }()
	path := filepath.Join(dir, "device.ini")
	if err := os.WriteFile(path, []byte("[core]\nsocket="+socket+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := helpRun("tasks", "--config", path)
	if code != 1 || out != response || stderr != "" || requests.Load() != 1 {
		t.Fatalf("Core error response/exit code changed: code=%d out=%s stderr=%s requests=%d", code, out, stderr, requests.Load())
	}
}
