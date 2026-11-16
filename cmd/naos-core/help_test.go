package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"naos.local/core/internal/config"
)

func helpRun(args ...string) (int, string, string) {
	var out, stderr bytes.Buffer
	code := run(args, &out, &stderr)
	return code, out.String(), stderr.String()
}

func TestRootHelpListsCommandPurposesWithoutConfiguration(t *testing.T) {
	unreadable := t.TempDir() // Reading a directory as an INI fails even as root.
	cases := [][]string{nil, {"-h"}, {"--help"}, {"help"}, {"--help", "--config", unreadable}, {"-h", "--config", unreadable}}
	for _, args := range cases {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 0 || stderr != "" || !strings.Contains(strings.ToUpper(out), "USAGE:") || !strings.Contains(strings.ToUpper(out), "COMMANDS:") {
				t.Fatalf("args=%v code=%d out=%s stderr=%s", args, code, out, stderr)
			}
			for _, command := range []string{"serve", "oem", "containers", "reboot", "recovery", "update", "tasks", "task", "hawkbit"} {
				found := false
				for _, line := range strings.Split(out, "\n") {
					fields := strings.Fields(line)
					if len(fields) > 1 && fields[0] == command {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("command %q has no visible purpose in root help", command)
				}
			}
		})
	}
}

func TestEveryCommandHelpSkipsUnreadableConfiguration(t *testing.T) {
	unreadable := t.TempDir()
	commands := []struct{ name, purpose string }{{"serve", "foreground"}, {"oem", "sn"}, {"containers", "container"}, {"reboot", "reboot"}, {"recovery", "userdata"}, {"update", "rauc"}, {"tasks", "task"}, {"task", "task"}, {"hawkbit", "status"}}
	for _, command := range commands {
		for _, args := range [][]string{{command.name, "--help"}, {command.name, "--config", unreadable, "--help"}, {"help", command.name}} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				code, out, stderr := helpRun(args...)
				if code != 0 || stderr != "" || !strings.Contains(strings.ToUpper(out), "USAGE:") || !strings.Contains(strings.ToLower(out), command.purpose) {
					t.Fatalf("args=%v code=%d out=%s stderr=%s", args, code, out, stderr)
				}
			})
		}
	}
}

func TestHawkbitHelpAndBareCommandNeverReadConfiguration(t *testing.T) {
	unreadable := t.TempDir()
	for _, args := range [][]string{{"hawkbit"}, {"hawkbit", "--config", unreadable}, {"hawkbit", "status", "--help"}, {"hawkbit", "status", "--config", unreadable, "--help"}, {"hawkbit", "check", "--config=" + unreadable, "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 0 || stderr != "" || !strings.Contains(strings.ToUpper(out), "USAGE:") || !strings.Contains(out, "hawkbit") {
				t.Fatalf("args=%v code=%d out=%s stderr=%s", args, code, out, stderr)
			}
		})
	}
}

func TestInvalidCLIArgumentsRejectedBeforeConfiguration(t *testing.T) {
	unreadable := t.TempDir()
	for _, args := range [][]string{
		{"unknown", "--config", unreadable}, {"help", "unknown", "--config", unreadable},
		{"hawkbit", "unknown", "--config", unreadable}, {"hawkbit", "status", "extra", "--config", unreadable},
		{"containers", "destroy", "demo", "--config", unreadable}, {"containers", "start", "--config", unreadable},
		{"task", "--config", unreadable}, {"serve", "extra", "--config", unreadable}, {"update", "one", "two", "--config", unreadable},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 2 || strings.Contains(out+stderr, unreadable) {
				t.Fatalf("must reject before config read: args=%v code=%d out=%s stderr=%s", args, code, out, stderr)
			}
		})
	}
}

func TestHawkbitCheckDirectHTTPWorksDisabledWithoutCore(t *testing.T) {
	const token = "test-cli-target-token"
	for _, responseStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(fmt.Sprint(responseStatus), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/DEFAULT/controller/v1/cli-help-test" || r.Header.Get("Authorization") != "TargetToken "+token {
					t.Errorf("unexpected token-check request: method=%s path=%s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(responseStatus)
				if responseStatus == http.StatusOK {
					_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}},"_links":{}}`))
				} else {
					_, _ = w.Write([]byte(`{"error":"fixture authorization rejected"}`))
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			state := filepath.Join(dir, "state")
			if err := os.Mkdir(state, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(dir, "device.ini")
			content := fmt.Sprintf("[core]\nsocket=%s\nstate_dir=%s\n[hawkbit]\nenabled=false\nserver_url=%s\ntenant=DEFAULT\ncontroller_id=cli-help-test\ntoken=%s\ntimeout=1s\n", filepath.Join(dir, "no-core.sock"), state, server.URL, token)
			if err := os.WriteFile(cfg, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"hawkbit", "check", "--config", cfg}
			if responseStatus == http.StatusOK {
				args = []string{"hawkbit", "--config", cfg, "check"}
			}
			code, out, stderr := helpRun(args...)
			var result struct {
				Valid      bool   `json:"valid"`
				HTTPStatus int    `json:"http_status"`
				ErrorCode  string `json:"error_code"`
			}
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatalf("check did not return JSON: %s; stderr=%s; error=%v", out, stderr, err)
			}
			wantCode := 0
			if responseStatus != http.StatusOK {
				wantCode = 1
			}
			if code != wantCode || result.HTTPStatus != responseStatus || result.Valid != (responseStatus == http.StatusOK) || requests.Load() != 1 {
				t.Fatalf("code=%d result=%+v requests=%d stderr=%s", code, result, requests.Load(), stderr)
			}
			if responseStatus == http.StatusUnauthorized && result.ErrorCode != "UNAUTHORIZED" {
				t.Fatalf("401 classification: %+v", result)
			}
			if strings.Contains(out+stderr, token) {
				t.Fatal("check output leaked configured token")
			}
			entries, err := os.ReadDir(state)
			if err != nil || len(entries) != 0 {
				t.Fatalf("read-only check wrote runtime state: %v %v", entries, err)
			}
		})
	}
}

func TestHawkbitStatusRunUsesCoreUnixEndpoint(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "core.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/hawkbit" {
			t.Errorf("status request=%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"enabled\":false,\"last_poll_status\":200}\n"))
	})}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	defer func() { _ = server.Close(); <-finished }()
	cfg := filepath.Join(dir, "device.ini")
	content := fmt.Sprintf("[core]\nsocket=%s\nstate_dir=%s\n[hawkbit]\nenabled=false\ncontroller_id=cli-status-test\n", socket, filepath.Join(dir, "state"))
	if err := os.WriteFile(cfg, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := helpRun("hawkbit", "status", "--config", cfg)
	if code != 0 || requests.Load() != 1 || !strings.Contains(out, `"last_poll_status":200`) {
		t.Fatalf("status did not use local Core endpoint: code=%d out=%s stderr=%s requests=%d", code, out, stderr, requests.Load())
	}
}

func TestHawkbitCheckPersistsOneFallbackIdentityInINI(t *testing.T) {
	const token = "test-cli-gateway-token"
	generated := regexp.MustCompile(`^NN[A-Za-z0-9]{18}$`)
	observed := make(chan string, 2)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		const prefix = "/DEFAULT/controller/v1/"
		id := strings.TrimPrefix(r.URL.Path, prefix)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) || !generated.MatchString(id) || r.Header.Get("Authorization") != "GatewayToken "+token {
			t.Errorf("unexpected generated-identity check: method=%s path=%s", r.Method, r.URL.Path)
		}
		observed <- id
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}},"_links":{}}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "device.ini")
	original := fmt.Sprintf("# Preserve this CLI fixture comment.\n[platform]\nsoc=unsupported\n\n[core]\nsocket=%s\nstate_dir=%s\n\n[hawkbit]\nenabled=false\nserver_url=%s\ntenant=DEFAULT\ncontroller_id=\ntoken_type=gateway\ntoken=%s\ntimeout=1s\n# Preserve the final key comment.\npoll_interval=4m # Keep this setting and inline comment.\n", filepath.Join(dir, "no-core.sock"), state, server.URL, token)
	if err := os.WriteFile(cfg, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	beforeConfig, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var firstID string
	for round := 0; round < 2; round++ {
		code, out, stderr := helpRun("hawkbit", "check", "--config", cfg)
		if code != 0 || !strings.Contains(out, `"valid":true`) || strings.Contains(out+stderr, token) {
			t.Fatalf("check round %d: code=%d out=%s stderr=%s", round, code, out, stderr)
		}
		id := <-observed
		if !generated.MatchString(id) {
			t.Fatalf("fallback ID %q does not match NN + 18 alphanumeric characters", id)
		}
		if round == 0 {
			firstID = id
		} else if id != firstID {
			t.Fatalf("second check changed controller identity: %s -> %s", firstID, id)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d, expected exactly one per check", requests.Load())
	}
	updated, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	afterConfig, err := config.Load(cfg)
	if err != nil || afterConfig.Hawkbit.ControllerID != firstID {
		t.Fatal("identity persistence did not save the generated controller ID")
	}
	afterConfig.Hawkbit.ControllerID = beforeConfig.Hawkbit.ControllerID
	if !reflect.DeepEqual(beforeConfig, afterConfig) {
		t.Fatal("identity persistence changed another configuration value")
	}
	for _, comment := range []string{"Preserve this CLI fixture comment.", "Keep this setting and inline comment.", "Preserve the final key comment."} {
		if !strings.Contains(string(updated), comment) {
			t.Errorf("identity persistence lost an unrelated comment: %s", comment)
		}
	}
	info, err := os.Stat(cfg)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("updated INI permissions: info=%v error=%v", info, err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 0 {
		t.Fatalf("identity created a second state file: entries=%v error=%v", entries, err)
	}
}
