package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"naos.local/core/internal/systeminfo"
)

func TestSystemInfoWithoutHawkbit(t *testing.T) {
	s := services()
	info := systeminfo.Info{Version: "1.2.3", BuildID: "build-123", Machine: "example-board"}
	calls := 0
	s.System = func() (systeminfo.Info, error) { calls++; return info, nil }
	h := New(s)
	for _, version := range []string{"1.2.3", "1.2.4"} {
		info.Version = version
		w := request(h, http.MethodGet, "/v1/system", "")
		var got map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || len(got) != 3 || got["version"] != version || got["build_id"] != info.BuildID || got["machine"] != info.Machine {
			t.Fatalf("system response: %d %s (%v)", w.Code, w.Body.String(), err)
		}
		if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("system response is not uncached JSON")
		}
	}
	if calls != 2 {
		t.Fatalf("system metadata calls = %d; want 2", calls)
	}
	w := request(h, http.MethodPost, "/v1/system", "")
	if w.Code != http.StatusMethodNotAllowed || calls != 2 {
		t.Fatalf("POST system response: %d, calls=%d", w.Code, calls)
	}
}

func TestSystemInfoOptionalFields(t *testing.T) {
	s := services()
	s.System = func() (systeminfo.Info, error) { return systeminfo.Info{Version: "1.2.3"}, nil }
	w := request(New(s), http.MethodGet, "/v1/system", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"version":"1.2.3","build_id":"","machine":""}` {
		t.Fatalf("optional system fields response: %d %s", w.Code, w.Body.String())
	}
}

func TestSystemInfoUnavailable(t *testing.T) {
	for _, backendMissing := range []bool{true, false} {
		s := services()
		if !backendMissing {
			s.System = func() (systeminfo.Info, error) {
				return systeminfo.Info{Version: "partial-version"}, errors.New("private metadata read error")
			}
		}
		w := request(New(s), http.MethodGet, "/v1/system", "")
		if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "SYSTEM_INFO_UNAVAILABLE" || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "partial-version") {
			t.Fatalf("unavailable system response: %d %s", w.Code, w.Body.String())
		}
	}
}
