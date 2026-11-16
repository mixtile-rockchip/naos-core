package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/recovery"
)

func TestRecoveryRefusesBusyFailedAndWrongMethod(t *testing.T) {
	for _, c := range []struct {
		name    string
		busy    bool
		failure error
		want    int
		calls   int32
	}{
		{"busy", true, nil, http.StatusConflict, 0},
		{"write-failed", false, errors.New("sync failed"), http.StatusServiceUnavailable, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := services()
			var marked, rebooted atomic.Int32
			s.Busy = func(context.Context) (bool, error) { return c.busy, nil }
			s.Recovery = func(context.Context) error { marked.Add(1); return c.failure }
			s.Reboot = func() error { rebooted.Add(1); return nil }
			h := New(s)
			w := request(h, http.MethodGet, "/v1/recovery", "")
			if w.Code != http.StatusMethodNotAllowed || marked.Load() != 0 {
				t.Fatal("GET invoked recovery")
			}
			w = request(h, http.MethodPost, "/v1/recovery", "")
			if w.Code != c.want || marked.Load() != c.calls || rebooted.Load() != 0 {
				t.Fatalf("response %d %s, marked=%d rebooted=%d", w.Code, w.Body.String(), marked.Load(), rebooted.Load())
			}
			if strings.Contains(w.Body.String(), `"accepted"`) {
				t.Fatal("failed request reported accepted")
			}
		})
	}
}

func TestRecoveryFlushesBeforeAcceptedAndBlocksCompetingActions(t *testing.T) {
	s := services()
	entered, release, ready, rebooted := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(ready)
	s.Recovery = func(context.Context) error { close(entered); <-release; return nil }
	s.Reboot = func() error { close(rebooted); <-ready; return errors.New("injected reboot failure") }
	h := New(s)
	response := make(chan int, 1)
	go func() { response <- request(h, http.MethodPost, "/v1/recovery", "").Code }()
	<-entered
	select {
	case <-response:
		t.Fatal("accepted before durable marker callback completed")
	default:
	}
	close(release)
	if code := <-response; code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	select {
	case <-rebooted:
	case <-time.After(2 * time.Second):
		t.Fatal("reboot not requested")
	}
	for _, path := range []string{"/v1/reboot", "/v1/recovery", "/v1/update"} {
		body := ""
		if path == "/v1/update" {
			body = updateJSON(bundle(t))
		}
		w := request(h, http.MethodPost, path, body)
		if w.Code != http.StatusConflict || errorCode(t, w) != "REBOOT_PENDING" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestUncertainRecoveryWriteRejectsWithoutAllowingInstall(t *testing.T) {
	s := services()
	var installs, reboots atomic.Int32
	s.Recovery = func(context.Context) error { return recovery.ErrUncertain }
	s.Update = func(context.Context, string) error { installs.Add(1); return nil }
	s.Reboot = func() error { reboots.Add(1); return nil }
	h := New(s)
	w := request(h, http.MethodPost, "/v1/recovery", "")
	if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "RECOVERY_FAILED" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = request(h, http.MethodPost, "/v1/update", updateJSON(bundle(t)))
	if w.Code != http.StatusConflict || installs.Load() != 0 || reboots.Load() != 0 {
		t.Fatalf("uncertain write lost guard: %d %s", w.Code, w.Body.String())
	}
}
