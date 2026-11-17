package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"naos.local/core/internal/container"
	"naos.local/core/internal/mdns"
	"naos.local/core/internal/oem"
	"naos.local/core/internal/operation"
	"naos.local/core/internal/recovery"
	"naos.local/core/internal/systeminfo"
	"naos.local/core/internal/update"
)

type MDNSManager interface {
	Put(context.Context, string, mdns.Service) (mdns.Registration, error)
	List(context.Context) ([]mdns.Registration, error)
	Delete(context.Context, string) error
}

type Services struct {
	System          func() (systeminfo.Info, error)
	OEM             func() (oem.Info, error)
	Containers      func(context.Context) ([]container.State, error)
	Update          func(context.Context, string) error
	UpdateStatus    func(context.Context) (update.Status, error)
	Busy            func(context.Context) (bool, error)
	Reboot          func() error
	Recovery        func(context.Context) error
	MDNS            MDNSManager
	Log             *log.Logger
	Gate            *operation.Gate
	InstallTask     func(context.Context, string, string) (update.Task, error)
	Tasks           func() ([]update.Task, error)
	Task            func(string) (update.Task, error)
	HawkbitStatus   func() any
	HawkbitReload   func(context.Context, string) (applied bool, pending bool, err error)
	ContainerChange func(context.Context, string, string) error
}

type api struct {
	services   Services
	actions    sync.Mutex
	rebooting  bool
	recovering bool
}

func New(services Services) http.Handler {
	a := &api{services: services}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/system", a.system)
	mux.HandleFunc("GET /v1/oem", a.oem)
	mux.HandleFunc("GET /v1/containers", a.containers)
	mux.HandleFunc("POST /v1/containers/{id}/{action}", a.changeContainer)
	mux.HandleFunc("POST /v1/reboot", a.reboot)
	mux.HandleFunc("POST /v1/recovery", a.recovery)
	mux.HandleFunc("POST /v1/update", a.install)
	mux.HandleFunc("GET /v1/update", a.updateStatus)
	mux.HandleFunc("GET /v1/update-tasks", a.tasks)
	mux.HandleFunc("GET /v1/update-tasks/{id}", a.task)
	mux.HandleFunc("GET /v1/hawkbit", a.hawkbit)
	mux.HandleFunc("POST /v1/hawkbit/reload", a.reloadHawkbit)
	mux.HandleFunc("PUT /v1/mdns/services/{id}", a.putMDNS)
	mux.HandleFunc("GET /v1/mdns/services", a.listMDNS)
	mux.HandleFunc("DELETE /v1/mdns/services/{id}", a.deleteMDNS)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// These local control endpoints are not a cross-origin browser API.
		mutates := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		if mutates && (r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
			failure(w, http.StatusForbidden, "CROSS_ORIGIN", "cross-origin control requests are not allowed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (a *api) oem(w http.ResponseWriter, r *http.Request) {
	info, err := a.services.OEM()
	if errors.Is(err, oem.ErrUnsupported) {
		failure(w, http.StatusNotImplemented, "OEM_UNSUPPORTED", "OEM requires platform.soc=rk3588")
		return
	}
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "OEM_READ_FAILED", err.Error())
		return
	}
	sn, mac := info.Strings()
	respond(w, http.StatusOK, map[string]string{"sn": sn, "mac": mac})
}

func (a *api) containers(w http.ResponseWriter, r *http.Request) {
	states, err := a.services.Containers(r.Context())
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "CONTAINERS_UNAVAILABLE", err.Error())
		return
	}
	if states == nil {
		states = []container.State{}
	}
	respond(w, http.StatusOK, map[string]any{"containers": states})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

func (a *api) install(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Path      string `json:"path"`
		RequestID string `json:"request_id,omitempty"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		failure(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if !filepath.IsAbs(request.Path) {
		failure(w, http.StatusBadRequest, "INVALID_PATH", "path must be an absolute local file path")
		return
	}
	request.Path = filepath.Clean(request.Path)
	// An already durable request remains idempotent even if its bundle has
	// subsequently been removed. The manager repeats this check atomically.
	if request.RequestID != "" && a.services.Tasks != nil {
		tasks, err := a.services.Tasks()
		if err != nil {
			updateFailure(w, err)
			return
		}
		for _, task := range tasks {
			if task.RequestID != request.RequestID {
				continue
			}
			if task.Source != "local" || task.Path != request.Path {
				updateFailure(w, update.ErrConflict)
				return
			}
			respond(w, http.StatusAccepted, map[string]string{"status": "accepted", "path": task.Path, "task_id": task.ID, "state": task.State})
			return
		}
	}
	info, err := os.Lstat(request.Path)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		failure(w, status, "INVALID_PATH", err.Error())
		return
	}
	if !info.Mode().IsRegular() {
		failure(w, http.StatusBadRequest, "INVALID_PATH", "path must name a regular file")
		return
	}
	a.actions.Lock()
	defer a.actions.Unlock()
	if a.rebooting {
		failure(w, http.StatusConflict, "REBOOT_PENDING", "device reboot is pending")
		return
	}
	if a.services.InstallTask != nil {
		task, err := a.services.InstallTask(r.Context(), request.Path, request.RequestID)
		if err != nil {
			updateFailure(w, err)
			return
		}
		respond(w, http.StatusAccepted, map[string]string{"status": "accepted", "path": request.Path, "task_id": task.ID, "state": task.State})
		return
	}
	if err := a.services.Update(r.Context(), request.Path); err != nil {
		status, code := http.StatusServiceUnavailable, "UPDATE_REJECTED"
		if errors.Is(err, update.ErrBusy) {
			status, code = http.StatusConflict, "UPDATE_BUSY"
		}
		failure(w, status, code, err.Error())
		return
	}
	respond(w, http.StatusAccepted, map[string]string{"status": "accepted", "path": request.Path})
}

func (a *api) updateStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.services.UpdateStatus(r.Context())
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE", err.Error())
		return
	}
	respond(w, http.StatusOK, status)
}

func (a *api) reboot(w http.ResponseWriter, r *http.Request) {
	a.restart(w, r, false)
}

func (a *api) recovery(w http.ResponseWriter, r *http.Request) {
	a.restart(w, r, true)
}

func (a *api) restart(w http.ResponseWriter, r *http.Request, recoverData bool) {
	a.actions.Lock()
	defer a.actions.Unlock()
	if a.rebooting {
		failure(w, http.StatusConflict, "REBOOT_PENDING", "device reboot is pending")
		return
	}
	var lease *operation.Lease
	retain := false
	if a.services.Gate != nil {
		kind := "reboot"
		if recoverData {
			kind = "recovery"
		}
		var err error
		lease, err = a.services.Gate.TryAcquire(kind)
		if err != nil {
			failure(w, http.StatusConflict, "UPDATE_BUSY", "another device operation is active")
			return
		}
		defer func() {
			if !retain {
				lease.Release()
			}
		}()
	}
	busy, err := a.services.Busy(r.Context())
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "UPDATE_UNAVAILABLE", err.Error())
		return
	}
	if busy {
		failure(w, http.StatusConflict, "UPDATE_BUSY", "cannot restart while RAUC is installing")
		return
	}
	if recoverData {
		if a.services.Recovery == nil {
			failure(w, http.StatusServiceUnavailable, "RECOVERY_UNAVAILABLE", "recovery is not configured")
			return
		}
		if err := a.services.Recovery(r.Context()); err != nil {
			if errors.Is(err, recovery.ErrUncertain) {
				a.rebooting, a.recovering = true, true
				retain = true
			}
			failure(w, http.StatusServiceUnavailable, "RECOVERY_FAILED", err.Error())
			return
		}
		a.recovering = true
	}
	a.rebooting = true
	retain = true
	respond(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	if flush, ok := w.(http.Flusher); ok {
		flush.Flush()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := a.services.Reboot(); err != nil {
			if a.services.Log != nil {
				a.services.Log.Print(fmt.Errorf("reboot failed: %w", err))
			}
			a.actions.Lock()
			// A durable recovery request must continue blocking installs even if
			// reboot fails. It remains queued for the next manual restart.
			if !a.recovering {
				a.rebooting = false
				lease.Release()
			}
			a.actions.Unlock()
		}
	}()
}
