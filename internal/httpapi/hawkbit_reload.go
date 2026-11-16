package httpapi

import (
	"net/http"
	"path/filepath"
	"strings"

	"naos.local/core/internal/server"
)

func (a *api) reloadHawkbit(w http.ResponseWriter, r *http.Request) {
	if !server.IsUnixRequest(r) {
		failure(w, http.StatusForbidden, "UNIX_REQUIRED", "hawkBit reload requires the local Unix socket")
		return
	}
	var request struct {
		ConfigPath string `json:"config_path"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		failure(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid hawkBit reload request")
		return
	}
	if !filepath.IsAbs(request.ConfigPath) || strings.IndexByte(request.ConfigPath, 0) >= 0 {
		failure(w, http.StatusBadRequest, "INVALID_PATH", "config_path must be an absolute local file path")
		return
	}
	if a.services.HawkbitReload == nil {
		failure(w, http.StatusServiceUnavailable, "APPLY_FAILED", "hawkBit configuration reload is unavailable")
		return
	}
	applied, pending, err := a.services.HawkbitReload(r.Context(), filepath.Clean(request.ConfigPath))
	if err != nil || applied == pending {
		failure(w, http.StatusServiceUnavailable, "APPLY_FAILED", "cannot apply hawkBit configuration")
		return
	}
	status := http.StatusOK
	if pending {
		status = http.StatusAccepted
	}
	respond(w, status, struct {
		Applied bool `json:"applied"`
		Pending bool `json:"pending"`
	}{Applied: applied, Pending: pending})
}
