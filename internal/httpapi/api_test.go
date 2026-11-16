package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/container"
	"naos.local/core/internal/oem"
	"naos.local/core/internal/update"
)

func services() Services {
	return Services{
		OEM:          func() (oem.Info, error) { return oem.Info{}, oem.ErrUnsupported },
		Containers:   func(context.Context) ([]container.State, error) { return nil, nil },
		Update:       func(context.Context, string) error { return nil },
		UpdateStatus: func(context.Context) (update.Status, error) { return update.Status{Operation: "idle"}, nil },
		Busy:         func(context.Context) (bool, error) { return false, nil },
		Reboot:       func() error { return errors.New("no reboot configured in test") },
	}
}

func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var result struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Error.Code == "" || result.Error.Message == "" {
		t.Fatalf("invalid error JSON: %s; error=%v", w.Body.String(), err)
	}
	return result.Error.Code
}

func bundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "update.raucb")
	if err := os.WriteFile(path, []byte("fixture is not a signed bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func updateJSON(path string) string {
	data, _ := json.Marshal(map[string]string{"path": path})
	return string(data)
}

func TestHealthAndOEM(t *testing.T) {
	s := services()
	info := oem.Info{MAC: [6]byte{0x02, 0x11, 0x22, 0xaa, 0xbb, 0xcc}}
	copy(info.SN[:], "1234567890ABCDEF")
	s.OEM = func() (oem.Info, error) { return info, nil }
	h := New(s)
	w := request(h, http.MethodGet, "/healthz", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("health response: %d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodGet, "/v1/oem", "")
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || got["sn"] != "1234567890ABCDEF" || got["mac"] != "02:11:22:AA:BB:CC" {
		t.Fatalf("OEM response: %d %s (%v)", w.Code, w.Body.String(), err)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("OEM response is not uncached JSON")
	}

	s.OEM = func() (oem.Info, error) { return oem.Info{}, oem.ErrUnsupported }
	w = request(New(s), http.MethodGet, "/v1/oem", "")
	if w.Code != http.StatusNotImplemented || errorCode(t, w) != "OEM_UNSUPPORTED" {
		t.Fatalf("unsupported OEM response: %d %s", w.Code, w.Body.String())
	}
}

func TestContainersEmptyArrayAndUnavailable(t *testing.T) {
	s := services()
	w := request(New(s), http.MethodGet, "/v1/containers", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"containers":[]}` {
		t.Fatalf("empty containers response: %d %s", w.Code, w.Body.String())
	}
	s.Containers = func(context.Context) ([]container.State, error) { return nil, errors.New("socket unavailable") }
	w = request(New(s), http.MethodGet, "/v1/containers", "")
	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "CONTAINERS_UNAVAILABLE" {
		t.Fatalf("unavailable containers response: %d %s", w.Code, w.Body.String())
	}
}

func TestUpdateAcceptsAbsoluteRegularFileWithoutClaimingCompletion(t *testing.T) {
	path := bundle(t)
	s := services()
	var submitted string
	s.Update = func(_ context.Context, path string) error { submitted = path; return nil }
	w := request(New(s), http.MethodPost, "/v1/update", updateJSON(path))
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusAccepted || got["status"] != "accepted" || got["path"] != path || submitted != path {
		t.Fatalf("update response: %d %s, submitted=%q error=%v", w.Code, w.Body.String(), submitted, err)
	}
}

func TestUpdateRejectsInvalidInputBeforeBackend(t *testing.T) {
	path := bundle(t)
	link := filepath.Join(t.TempDir(), "link.raucb")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, body, contentType string
		status                  int
	}{
		{"relative", updateJSON("update.raucb"), "application/json", http.StatusBadRequest},
		{"missing", updateJSON(filepath.Join(t.TempDir(), "missing.raucb")), "application/json", http.StatusNotFound},
		{"directory", updateJSON(t.TempDir()), "application/json", http.StatusBadRequest},
		{"symlink", updateJSON(link), "application/json", http.StatusBadRequest},
		{"unknownField", fmt.Sprintf(`{"path":%q,"skip_verify":true}`, path), "application/json", http.StatusBadRequest},
		{"trailingJSON", updateJSON(path) + " {}", "application/json", http.StatusBadRequest},
		{"oversize", updateJSON("/" + strings.Repeat("a", 4096)), "application/json", http.StatusBadRequest},
		{"contentType", updateJSON(path), "text/plain", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := services()
			calls := 0
			s.Update = func(context.Context, string) error { calls++; return nil }
			r := httptest.NewRequest(http.MethodPost, "/v1/update", strings.NewReader(c.body))
			r.Header.Set("Content-Type", c.contentType)
			w := httptest.NewRecorder()
			New(s).ServeHTTP(w, r)
			if w.Code != c.status || calls != 0 {
				t.Fatalf("invalid input reached backend or unexpected response: %d %s, calls=%d", w.Code, w.Body.String(), calls)
			}
			errorCode(t, w)
		})
	}
}

func TestUpdateBusyAndStatus(t *testing.T) {
	s := services()
	s.Update = func(context.Context, string) error { return fmt.Errorf("install rejected: %w", update.ErrBusy) }
	w := request(New(s), http.MethodPost, "/v1/update", updateJSON(bundle(t)))
	if w.Code != http.StatusConflict || errorCode(t, w) != "UPDATE_BUSY" {
		t.Fatalf("busy response: %d %s", w.Code, w.Body.String())
	}
	s.UpdateStatus = func(context.Context) (update.Status, error) {
		return update.Status{Operation: "installing", Pending: true, Path: "/userdata/test.raucb", Progress: update.Progress{Percentage: 42, Message: "copying", Depth: 2}}, nil
	}
	w = request(New(s), http.MethodGet, "/v1/update", "")
	var got update.Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || got.Operation != "installing" || got.Progress.Percentage != 42 || !got.Pending || got.Result != nil {
		t.Fatalf("update status response: %d %s (%v)", w.Code, w.Body.String(), err)
	}
}

func TestRebootMethodAndBusyGuardsHaveNoSideEffects(t *testing.T) {
	s := services()
	var calls atomic.Int32
	s.Reboot = func() error { calls.Add(1); return nil }
	w := request(New(s), http.MethodGet, "/v1/reboot", "")
	if w.Code != http.StatusMethodNotAllowed || calls.Load() != 0 {
		t.Fatalf("GET reboot response: %d, calls=%d", w.Code, calls.Load())
	}
	s.Busy = func(context.Context) (bool, error) { return true, nil }
	w = request(New(s), http.MethodPost, "/v1/reboot", "")
	if w.Code != http.StatusConflict || errorCode(t, w) != "UPDATE_BUSY" || calls.Load() != 0 {
		t.Fatalf("busy reboot response: %d %s, calls=%d", w.Code, w.Body.String(), calls.Load())
	}
}

func TestRebootReturnsAcceptedThenRunsOnceAndBlocksFurtherActions(t *testing.T) {
	s := services()
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	var rebootCalls, updateCalls atomic.Int32
	s.Reboot = func() error {
		if rebootCalls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil
	}
	s.Update = func(context.Context, string) error { updateCalls.Add(1); return nil }
	h := New(s)
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- request(h, http.MethodPost, "/v1/reboot", "") }()
	select {
	case w := <-response:
		if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"status":"accepted"`) {
			t.Fatalf("reboot response: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reboot handler waited for the reboot callback")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted reboot callback did not run")
	}
	w := request(h, http.MethodPost, "/v1/reboot", "")
	if w.Code != http.StatusConflict || errorCode(t, w) != "REBOOT_PENDING" {
		t.Fatalf("duplicate reboot response: %d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodPost, "/v1/update", updateJSON(bundle(t)))
	if w.Code != http.StatusConflict || errorCode(t, w) != "REBOOT_PENDING" || updateCalls.Load() != 0 || rebootCalls.Load() != 1 {
		t.Fatalf("update during reboot response: %d %s, calls update=%d reboot=%d", w.Code, w.Body.String(), updateCalls.Load(), rebootCalls.Load())
	}
}

func TestCrossOriginControlRequestsAreRejected(t *testing.T) {
	for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
		t.Run(header, func(t *testing.T) {
			s := services()
			var calls atomic.Int32
			s.Reboot = func() error { calls.Add(1); return nil }
			s.Update = func(context.Context, string) error { calls.Add(1); return nil }
			s.Recovery = func(context.Context) error { calls.Add(1); return nil }
			h := New(s)
			for _, path := range []string{"/v1/reboot", "/v1/update", "/v1/recovery"} {
				r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(updateJSON(bundle(t))))
				r.Header.Set("Content-Type", "application/json")
				value := "https://example.test"
				if header == "Sec-Fetch-Site" {
					value = "cross-site"
				}
				r.Header.Set(header, value)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden || errorCode(t, w) != "CROSS_ORIGIN" || calls.Load() != 0 {
					t.Fatalf("cross-origin action response: %d %s, calls=%d", w.Code, w.Body.String(), calls.Load())
				}
			}
		})
	}
}
