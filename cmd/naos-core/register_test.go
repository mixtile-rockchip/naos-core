package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

type registrationReply struct {
	Registered   bool   `json:"registered"`
	Saved        bool   `json:"saved"`
	HTTPStatus   int    `json:"http_status"`
	ControllerID string `json:"controller_id"`
	PollingSleep string `json:"polling_sleep"`
	ErrorCode    string `json:"error_code"`
}

func registrationJSON(t *testing.T, out string) registrationReply {
	t.Helper()
	var result registrationReply
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("registration did not return one JSON result: %v", err)
	}
	if !strings.Contains(out, `"registered":`) {
		t.Fatal("registration result omitted the registered field")
	}
	return result
}

func registrationINI(t *testing.T) (path, state string, original []byte) {
	t.Helper()
	dir := t.TempDir()
	path, state = filepath.Join(dir, "device.ini"), filepath.Join(dir, "untouched-state")
	original = []byte(fmt.Sprintf(`# Preserve unrelated configuration and comments.
[platform]
soc=rk3588

[http]
listen=127.0.0.1:9919

[core]
socket=/run/naos/register-test-no-core.sock
state_dir=%s

[hawkbit]
enabled=false # Registration must preserve this choice.
server_url=http://previous-server.invalid
tenant=PREVIOUS_TENANT
controller_id=PREVIOUS_DEVICE_ID
token=previous-ini-token-must-not-be-used
token_type=target
poll_interval=4m # Preserve polling configuration.
timeout=7s
download_path=%s

[watchdog]
enabled=false
device=/dev/watchdog0
timeout=30s
# Preserve the final key comment too.
feed_interval=10s
`, state, filepath.Join(state, "downloads")))
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	return path, state, original
}

func TestManualRegisterHelpDoesNotReadConfiguration(t *testing.T) {
	unreadable := t.TempDir()
	for _, args := range [][]string{
		{"hawkbit"},
		{"hawkbit", "register", "--help"},
		{"hawkbit", "register", "--config", unreadable, "--help"},
		{"hawkbit", "--config", unreadable, "register", "-h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out, stderr := helpRun(args...)
			if code != 0 || stderr != "" || !strings.Contains(out, "register") {
				t.Fatalf("registration help: args=%v code=%d stderr=%s", args, code, stderr)
			}
			if strings.Contains(strings.Join(args, " "), "register") {
				for _, option := range []string{"--server", "--tenant", "--token"} {
					if !strings.Contains(out, option) {
						t.Errorf("registration help omitted required option %s", option)
					}
				}
			}
		})
	}
}

func TestManualRegisterRequiresExplicitParametersBeforeConfigurationOrHTTP(t *testing.T) {
	const token = "explicit-register-token"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}}}`))
	}))
	defer server.Close()
	unreadable := t.TempDir()
	cases := [][]string{
		{"--tenant", "REGISTER_TENANT", "--token", token},
		{"--server", server.URL, "--token", token},
		{"--server", server.URL, "--tenant", "REGISTER_TENANT"},
		{"--server", "", "--tenant", "REGISTER_TENANT", "--token", token},
		{"--server", server.URL, "--tenant", "", "--token", token},
		{"--server", server.URL, "--tenant", "REGISTER_TENANT", "--token", ""},
	}
	for i, flags := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			args := append([]string{"hawkbit", "register", "--config", unreadable}, flags...)
			code, out, stderr := helpRun(args...)
			if code != 2 || !strings.Contains(strings.ToUpper(out+stderr), "USAGE:") || strings.Contains(out+stderr, unreadable) {
				t.Fatalf("required arguments were not rejected before reading the save target: code=%d", code)
			}
			if strings.Contains(out+stderr, token) {
				t.Fatal("missing-argument error leaked a supplied token")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("incomplete registration made %d network requests", requests.Load())
	}
}

func TestManualRegisterUsesOnlyExplicitCredentialsAndGeneratesFreshIdentity(t *testing.T) {
	const token = "explicit-register-gateway-token"
	const tenant = "REGISTER_TENANT"
	generated := regexp.MustCompile(`^NN[A-Za-z0-9]{18}$`)
	ids := make(chan string, 2)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		const prefix = "/" + tenant + "/controller/v1/"
		id := strings.TrimPrefix(r.URL.Path, prefix)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, prefix) || !generated.MatchString(id) || r.Header.Get("Authorization") != "GatewayToken "+token {
			t.Errorf("registration ignored explicit inputs or used an old INI identity: method=%s path=%s", r.Method, r.URL.Path)
		}
		ids <- id
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}},"_links":{"deploymentBase":{"href":"http://unused.invalid/must-not-follow"}}}`))
	}))
	defer server.Close()
	path, state, _ := registrationINI(t)
	baseline, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var previousID string
	for round := 0; round < 2; round++ {
		args := []string{"hawkbit", "register", "--server", server.URL, "--tenant", tenant, "--token", token, "--config", path}
		if round == 1 {
			args = []string{"hawkbit", "--config", path, "register", "--token", token, "--tenant", tenant, "--server", server.URL}
		}
		code, out, stderr := helpRun(args...)
		if strings.Contains(out+stderr, token) || strings.Contains(out+stderr, "previous-ini-token") {
			t.Fatal("registration leaked a token")
		}
		result := registrationJSON(t, out)
		if code != 0 || !result.Registered || !result.Saved || result.HTTPStatus != http.StatusOK || result.PollingSleep != "30s" || !generated.MatchString(result.ControllerID) {
			t.Fatalf("registration round %d: code=%d result=%+v stderr=%s", round, code, result, stderr)
		}
		if observed := <-ids; observed != result.ControllerID {
			t.Fatalf("returned ID %q differs from requested ID %q", result.ControllerID, observed)
		}
		if round > 0 && result.ControllerID == previousID {
			t.Fatal("manual registration reused the previously saved fallback identity")
		}
		previousID = result.ControllerID
		updated, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, comment := range []string{
			"Preserve unrelated configuration and comments.",
			"Registration must preserve this choice.",
			"Preserve polling configuration.",
			"Preserve the final key comment too.",
		} {
			if !bytes.Contains(updated, []byte(comment)) {
				t.Fatal("registration removed an existing comment")
			}
		}
		cfg, err := config.Load(path)
		expected := baseline
		expected.Hawkbit.Enabled = true
		expected.Hawkbit.ServerURL = server.URL
		expected.Hawkbit.Tenant = tenant
		expected.Hawkbit.Token = token
		expected.Hawkbit.ControllerID = result.ControllerID
		expected.Hawkbit.TokenType = "gateway"
		if err != nil || !reflect.DeepEqual(cfg, expected) {
			t.Fatal("successful registration did not save explicit inputs and the generated ID while preserving unrelated configuration")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("registered configuration is not private")
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("expected one DDI GET per registration; got %d requests", requests.Load())
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("manual registration created updater/task runtime state")
	}
}

func TestManualRegisterDoesNotSaveRejectedOrInvalidResponses(t *testing.T) {
	const token = "rejected-explicit-register-token"
	const privateResponse = "private-server-response-must-not-be-logged"
	for _, fixture := range []struct {
		name, body, errorCode string
		status                int
	}{
		{"rejected", token + ":" + privateResponse, "UNAUTHORIZED", http.StatusUnauthorized},
		{"invalid-DDI", `{"message":"` + privateResponse + `"}`, "RESPONSE", http.StatusOK},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(fixture.status)
				_, _ = w.Write([]byte(fixture.body))
			}))
			defer server.Close()
			path, state, original := registrationINI(t)
			code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", server.URL, "--tenant", "REGISTER_TENANT", "--token", token)
			if strings.Contains(out+stderr, token) || strings.Contains(out+stderr, privateResponse) {
				t.Fatal("registration failure leaked a token or response body")
			}
			result := registrationJSON(t, out)
			if code != 1 || result.Registered || result.Saved || result.HTTPStatus != fixture.status || result.ErrorCode != fixture.errorCode || requests.Load() != 1 {
				t.Fatalf("failed registration: code=%d result=%+v requests=%d", code, result, requests.Load())
			}
			updated, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, updated) {
				t.Fatal("failed registration changed the saved configuration")
			}
			if _, err := os.Stat(state); !os.IsNotExist(err) {
				t.Fatal("failed registration created runtime state")
			}
		})
	}
}

func TestManualRegisterRejectsInvalidExplicitValuesWithoutLeakingThem(t *testing.T) {
	const token = "explicit-register-validation-token"
	const secret = "sensitive-invalid-register-value"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}}}`))
	}))
	defer server.Close()
	for _, fixture := range []struct{ name, server, tenant, token string }{
		{"URL-credentials", strings.Replace(server.URL, "http://", "http://user:"+secret+"@", 1), "REGISTER_TENANT", token},
		{"URL-query", server.URL + "?token=" + secret, "REGISTER_TENANT", token},
		{"tenant-whitespace", server.URL, "invalid\n" + secret, token},
		{"token-whitespace", server.URL, "REGISTER_TENANT", "invalid " + secret},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path, _, original := registrationINI(t)
			code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", fixture.server, "--tenant", fixture.tenant, "--token", fixture.token)
			if code == 0 || strings.Contains(out+stderr, token) || strings.Contains(out+stderr, secret) {
				t.Fatalf("invalid registration was accepted or leaked an input: code=%d", code)
			}
			updated, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, updated) {
				t.Fatal("invalid explicit registration values changed the INI")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid explicit registration made %d network requests", requests.Load())
	}
}

func TestManualRegisterReportsRemoteSuccessWhenSavingFails(t *testing.T) {
	const token = "explicit-register-save-failure-token"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"config":{"polling":{"sleep":"00:00:30"}}}`))
	}))
	defer server.Close()
	// A directory is not a valid INI target, even when tests run as root. It
	// must only be examined in the save phase, after the remote registration.
	path := t.TempDir()
	code, out, stderr := helpRun("hawkbit", "register", "--config", path, "--server", server.URL, "--tenant", "REGISTER_TENANT", "--token", token)
	if strings.Contains(out+stderr, token) {
		t.Fatal("persistence failure leaked the explicit token")
	}
	result := registrationJSON(t, out)
	if code != 1 || !result.Registered || result.Saved || result.HTTPStatus != http.StatusOK || result.ErrorCode != "PERSISTENCE" || requests.Load() != 1 {
		t.Fatalf("persistence failure lost remote success: code=%d result=%+v requests=%d", code, result, requests.Load())
	}
	if !regexp.MustCompile(`^NN[A-Za-z0-9]{18}$`).MatchString(result.ControllerID) {
		t.Fatal("persistence failure omitted the registered device identity")
	}
}
