package hawkbit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const attributesHeartbeatToken = "heartbeat-attributes-fixture-token"

func attributesVersionJSON(t *testing.T, version string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"version": version, "build_id": "heartbeat-fixture", "machine": "mixtile-core3588e-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func attributesHeartbeatRunner(t *testing.T, origin, versionFile string) (*Runner, *bytes.Buffer) {
	t.Helper()
	cfg := fixtureConfig(t, origin)
	cfg.Token, cfg.TokenType = attributesHeartbeatToken, "gateway"
	cfg.Timeout = 3 * time.Second
	logs := new(bytes.Buffer)
	runner, err := New(cfg, noopHooks(), log.New(logs, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	runner.options.directory = filepath.Join(dir, "not-created-runtime")
	if versionFile == "" {
		versionFile = filepath.Join(dir, "version.json")
	}
	runner.options.versionFile = versionFile
	runner.options.osReleaseFile = filepath.Join(dir, "os-release")
	if err := os.WriteFile(runner.options.versionFile, attributesVersionJSON(t, "1.2.3"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner.options.osReleaseFile, []byte("ID=alpine\nNAME=NAOS\nVERSION_ID=1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runner.transport.CloseIdleConnections)
	return runner, logs
}

func startAttributesHeartbeat(t *testing.T, runner *Runner) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runner.heartbeat(ctx)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("attribute heartbeat did not stop after cancellation")
		}
	}
	t.Cleanup(stop)
	return stop
}

func attributesHeartbeatData(t *testing.T, request *http.Request) map[string]string {
	t.Helper()
	if request.Method != http.MethodPut || request.URL.Path != "/DEFAULT/controller/v1/fixture-01/configData" {
		t.Error("attributes were not sent to the fixed local configData endpoint")
	}
	if request.Header.Get("Authorization") != "GatewayToken "+attributesHeartbeatToken || request.Header.Get("Content-Type") != "application/json" {
		t.Error("attribute request omitted the configured authentication or JSON content type")
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 16*1024))
	if err != nil {
		t.Error("cannot read the attribute request")
		return nil
	}
	if strings.Contains(string(body), attributesHeartbeatToken) {
		t.Error("attribute payload disclosed the authentication token")
	}
	var value struct {
		Mode string            `json:"mode"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &value); err != nil || value.Mode != "merge" || value.Data["system_name"] != "NAOS" {
		t.Error("attributes omitted the merge mode or NAOS system name")
	}
	return value.Data
}

func awaitAttributesPUT(t *testing.T, reports <-chan map[string]string, version string) {
	t.Helper()
	select {
	case report := <-reports:
		if report["system_version"] != version {
			t.Errorf("attribute report has system version %q; want %q", report["system_version"], version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat did not publish the expected attributes")
	}
}

func awaitAttributesState(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("heartbeat did not publish the expected state")
}

func assertAttributesSnapshotPrivate(t *testing.T, snapshot Snapshot) {
	t.Helper()
	public, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{attributesHeartbeatToken, "private-configData-response"} {
		if strings.Contains(string(public), private) {
			t.Error("heartbeat snapshot disclosed a token or private response body")
		}
	}
}

func TestHeartbeatAttributesFirstChangedAndRequestedReports(t *testing.T) {
	var gets, puts, foreignRequests atomic.Int32
	reports := make(chan map[string]string, 8)
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(foreign.Close)
	versionFile := filepath.Join(t.TempDir(), "version.json")
	changed := attributesVersionJSON(t, "1.2.4")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut {
			reports <- attributesHeartbeatData(t, request)
			puts.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != "/DEFAULT/controller/v1/fixture-01" || request.Header.Get("Authorization") != "GatewayToken "+attributesHeartbeatToken {
			t.Error("heartbeat GET used an unexpected endpoint or authentication")
		}
		n := gets.Add(1)
		links := map[string]any{}
		if n == 4 {
			if puts.Load() != 1 {
				t.Error("unchanged attributes were reported more than once over the first three GETs")
			}
			if err := os.WriteFile(versionFile, changed, 0600); err != nil {
				t.Error("cannot update the fixture version")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		if n == 5 {
			if puts.Load() != 2 {
				t.Error("changed system version was not reported on the preceding heartbeat")
			}
			links["configData"] = map[string]string{"href": foreign.URL + "/collect?token=" + attributesHeartbeatToken}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"config": map[string]any{"polling": map[string]string{"sleep": "00:00:01"}},
			"_links": links,
		})
	}))
	t.Cleanup(server.Close)
	runner, logs := attributesHeartbeatRunner(t, server.URL, versionFile)
	stop := startAttributesHeartbeat(t, runner)
	awaitAttributesPUT(t, reports, "1.2.3")
	awaitAttributesPUT(t, reports, "1.2.4")
	awaitAttributesPUT(t, reports, "1.2.4")
	awaitAttributesState(t, func() bool {
		snapshot := runner.Snapshot()
		return puts.Load() == 3 && snapshot.SystemVersion == "1.2.4" && snapshot.AttributesError == ""
	})
	stop()
	if gets.Load() != 5 || puts.Load() != 3 || foreignRequests.Load() != 0 {
		t.Errorf("unexpected heartbeat traffic: GET=%d PUT=%d foreign=%d", gets.Load(), puts.Load(), foreignRequests.Load())
	}
	assertAttributesSnapshotPrivate(t, runner.Snapshot())
	if strings.Contains(logs.String(), attributesHeartbeatToken) {
		t.Error("heartbeat logger disclosed the configured token")
	}
	if _, err := os.Stat(runner.options.directory); !os.IsNotExist(err) {
		t.Error("heartbeat-only reporting created updater runtime state")
	}
}

func TestHeartbeatAttributesRetryFailureWithoutStoppingHeartbeat(t *testing.T) {
	var gets, puts atomic.Int32
	reports := make(chan map[string]string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut {
			reports <- attributesHeartbeatData(t, request)
			if puts.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, "private-configData-response:"+attributesHeartbeatToken)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != "/DEFAULT/controller/v1/fixture-01" || request.Header.Get("Authorization") != "GatewayToken "+attributesHeartbeatToken {
			t.Error("retry heartbeat used an unexpected endpoint or authentication")
		}
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"config":{"polling":{"sleep":"00:00:01"}},"_links":{}}`)
	}))
	t.Cleanup(server.Close)
	runner, logs := attributesHeartbeatRunner(t, server.URL, "")
	stop := startAttributesHeartbeat(t, runner)
	awaitAttributesPUT(t, reports, "1.2.3")
	awaitAttributesState(t, func() bool { return runner.Snapshot().AttributesError != "" })
	first := runner.Snapshot()
	if first.Heartbeat.HTTPStatus != http.StatusOK || first.Heartbeat.Error != "" || first.Heartbeat.LastSuccess.IsZero() {
		t.Error("failed attribute reporting erased the successful heartbeat state")
	}
	assertAttributesSnapshotPrivate(t, first)
	awaitAttributesPUT(t, reports, "1.2.3")
	awaitAttributesState(t, func() bool {
		snapshot := runner.Snapshot()
		return gets.Load() >= 3 && snapshot.AttributesError == "" && snapshot.SystemVersion == "1.2.3"
	})
	stop()
	if gets.Load() < 3 || puts.Load() != 2 {
		t.Errorf("failed attributes were not retried exactly once: GET=%d PUT=%d", gets.Load(), puts.Load())
	}
	assertAttributesSnapshotPrivate(t, runner.Snapshot())
	if strings.Contains(logs.String(), attributesHeartbeatToken) || strings.Contains(logs.String(), "private-configData-response") {
		t.Error("attribute failure logging disclosed a token or private response body")
	}
}
