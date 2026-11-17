package httpapi

import "net/http"

func (a *api) system(w http.ResponseWriter, r *http.Request) {
	if a.services.System == nil {
		failure(w, http.StatusServiceUnavailable, "SYSTEM_INFO_UNAVAILABLE", "cannot read system version metadata")
		return
	}
	info, err := a.services.System()
	if err != nil {
		failure(w, http.StatusServiceUnavailable, "SYSTEM_INFO_UNAVAILABLE", "cannot read system version metadata")
		return
	}
	respond(w, http.StatusOK, info)
}
