package httpapi

import (
	"errors"
	"net/http"

	"naos.local/core/internal/mdns"
)

func mdnsFailure(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "MDNS_UNAVAILABLE"
	switch {
	case errors.Is(err, mdns.ErrInvalid):
		status, code = http.StatusBadRequest, "INVALID_MDNS_SERVICE"
	case errors.Is(err, mdns.ErrNotFound):
		status, code = http.StatusNotFound, "MDNS_NOT_FOUND"
	case errors.Is(err, mdns.ErrConflict):
		status, code = http.StatusConflict, "MDNS_CONFLICT"
	}
	failure(w, status, code, err.Error())
}

func (a *api) putMDNS(w http.ResponseWriter, r *http.Request) {
	var service mdns.Service
	if err := decodeJSON(w, r, &service); err != nil {
		failure(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if a.services.MDNS == nil {
		mdnsFailure(w, mdns.ErrUnavailable)
		return
	}
	registration, err := a.services.MDNS.Put(r.Context(), r.PathValue("id"), service)
	if err != nil {
		mdnsFailure(w, err)
		return
	}
	respond(w, http.StatusOK, registration)
}

func (a *api) listMDNS(w http.ResponseWriter, r *http.Request) {
	if a.services.MDNS == nil {
		mdnsFailure(w, mdns.ErrUnavailable)
		return
	}
	registrations, err := a.services.MDNS.List(r.Context())
	if err != nil {
		mdnsFailure(w, err)
		return
	}
	if registrations == nil {
		registrations = []mdns.Registration{}
	}
	respond(w, http.StatusOK, map[string]any{"services": registrations})
}

func (a *api) deleteMDNS(w http.ResponseWriter, r *http.Request) {
	if a.services.MDNS == nil {
		mdnsFailure(w, mdns.ErrUnavailable)
		return
	}
	if err := a.services.MDNS.Delete(r.Context(), r.PathValue("id")); err != nil {
		mdnsFailure(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
