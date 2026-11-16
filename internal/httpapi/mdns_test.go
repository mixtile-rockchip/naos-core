package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"naos.local/core/internal/mdns"
)

type mdnsBackend struct {
	put    func(context.Context, string, mdns.Service) (mdns.Registration, error)
	list   func(context.Context) ([]mdns.Registration, error)
	delete func(context.Context, string) error
}

func (b mdnsBackend) Put(ctx context.Context, id string, service mdns.Service) (mdns.Registration, error) {
	return b.put(ctx, id, service)
}

func (b mdnsBackend) List(ctx context.Context) ([]mdns.Registration, error) {
	return b.list(ctx)
}

func (b mdnsBackend) Delete(ctx context.Context, id string) error {
	return b.delete(ctx, id)
}

func mdnsRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const mlpJSON = `{"name":"客厅主控","type":"_mlp._tcp","port":1886,"txt":{"version":"1"}}`

func TestMDNSRoutesForwardServiceAndReturnPublication(t *testing.T) {
	wantService := mdns.Service{Name: "客厅主控", Type: "_mlp._tcp", Port: 1886, TXT: map[string]string{"version": "1"}}
	want := mdns.Registration{ID: "business-1", Service: wantService, State: "published"}
	want.Host = "SN12345678901234.local"
	var putCalls, listCalls, deleteCalls int
	s := services()
	s.MDNS = mdnsBackend{
		put: func(_ context.Context, id string, service mdns.Service) (mdns.Registration, error) {
			putCalls++
			if id != want.ID || !reflect.DeepEqual(service, wantService) {
				t.Fatalf("forwarded id=%q service=%+v", id, service)
			}
			return want, nil
		},
		list: func(context.Context) ([]mdns.Registration, error) {
			listCalls++
			return []mdns.Registration{want}, nil
		},
		delete: func(_ context.Context, id string) error {
			deleteCalls++
			if id != want.ID {
				t.Fatalf("delete id=%q", id)
			}
			return nil
		},
	}
	h := New(s)
	w := mdnsRequest(h, http.MethodPut, "/v1/mdns/services/business-1", mlpJSON)
	var registration mdns.Registration
	if err := json.Unmarshal(w.Body.Bytes(), &registration); err != nil || w.Code != http.StatusOK || !reflect.DeepEqual(registration, want) || putCalls != 1 {
		t.Fatalf("publication: status=%d body=%s calls=%d error=%v", w.Code, w.Body.String(), putCalls, err)
	}
	w = mdnsRequest(h, http.MethodGet, "/v1/mdns/services", "")
	var list struct {
		Services []mdns.Registration `json:"services"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != http.StatusOK || !reflect.DeepEqual(list.Services, []mdns.Registration{want}) || listCalls != 1 {
		t.Fatalf("list: status=%d body=%s calls=%d error=%v", w.Code, w.Body.String(), listCalls, err)
	}
	w = mdnsRequest(h, http.MethodDelete, "/v1/mdns/services/business-1", "")
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 || deleteCalls != 1 {
		t.Fatalf("delete: status=%d body=%s calls=%d", w.Code, w.Body.String(), deleteCalls)
	}
}

func TestMDNSRejectsMalformedJSONBeforeBackend(t *testing.T) {
	for _, body := range []string{
		`{"name":"x","type":"_mlp._tcp","port":1886,"unexpected":true}`,
		mlpJSON + " {}", "", `{"port":-1}`, `{"port":65536}`, `{"port":"1886"}`,
		`{"name":"` + strings.Repeat("x", 4096) + `"}`,
	} {
		t.Run(fmt.Sprintf("body%d", len(body)), func(t *testing.T) {
			s := services()
			calls := 0
			s.MDNS = mdnsBackend{put: func(context.Context, string, mdns.Service) (mdns.Registration, error) {
				calls++
				return mdns.Registration{}, nil
			}}
			w := mdnsRequest(New(s), http.MethodPut, "/v1/mdns/services/mlp", body)
			if w.Code != http.StatusBadRequest || errorCode(t, w) != "INVALID_REQUEST" || calls != 0 {
				t.Fatalf("malformed request: status=%d body=%s calls=%d", w.Code, w.Body.String(), calls)
			}
		})
	}
}

func TestMDNSRequiresJSONContentType(t *testing.T) {
	s := services()
	s.MDNS = mdnsBackend{put: func(context.Context, string, mdns.Service) (mdns.Registration, error) {
		t.Fatal("non-JSON request reached backend")
		return mdns.Registration{}, nil
	}}
	r := httptest.NewRequest(http.MethodPut, "/v1/mdns/services/mlp", strings.NewReader(mlpJSON))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	New(s).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "INVALID_REQUEST" {
		t.Fatalf("content type response: %d %s", w.Code, w.Body.String())
	}
}

func TestMDNSBackendErrorMapping(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{mdns.ErrInvalid, http.StatusBadRequest, "INVALID_MDNS_SERVICE"},
		{mdns.ErrNotFound, http.StatusNotFound, "MDNS_NOT_FOUND"},
		{mdns.ErrConflict, http.StatusConflict, "MDNS_CONFLICT"},
		{mdns.ErrUnavailable, http.StatusServiceUnavailable, "MDNS_UNAVAILABLE"},
		{errors.New("unexpected transport failure"), http.StatusServiceUnavailable, "MDNS_UNAVAILABLE"},
	} {
		for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodDelete} {
			t.Run(method+"/"+c.code, func(t *testing.T) {
				wrapped := fmt.Errorf("Avahi request failed: %w", c.err)
				s := services()
				s.MDNS = mdnsBackend{
					put: func(context.Context, string, mdns.Service) (mdns.Registration, error) {
						return mdns.Registration{}, wrapped
					},
					list:   func(context.Context) ([]mdns.Registration, error) { return nil, wrapped },
					delete: func(context.Context, string) error { return wrapped },
				}
				path := "/v1/mdns/services"
				if method != http.MethodGet {
					path += "/mlp"
				}
				w := mdnsRequest(New(s), method, path, mlpJSON)
				if w.Code != c.status || errorCode(t, w) != c.code {
					t.Fatalf("error mapping: status=%d body=%s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestMDNSMissingBackendAndEmptyList(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodPut, "/v1/mdns/services/mlp"},
		{http.MethodGet, "/v1/mdns/services"},
		{http.MethodDelete, "/v1/mdns/services/mlp"},
	} {
		w := mdnsRequest(New(services()), c.method, c.path, mlpJSON)
		if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "MDNS_UNAVAILABLE" {
			t.Fatalf("missing backend: status=%d body=%s", w.Code, w.Body.String())
		}
	}
	s := services()
	s.MDNS = mdnsBackend{list: func(context.Context) ([]mdns.Registration, error) { return nil, nil }}
	w := mdnsRequest(New(s), http.MethodGet, "/v1/mdns/services", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"services":[]}` {
		t.Fatalf("empty list: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMDNSCrossOriginMutationsDoNotReachBackend(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
			t.Run(method+"/"+header, func(t *testing.T) {
				calls := 0
				s := services()
				s.MDNS = mdnsBackend{
					put: func(context.Context, string, mdns.Service) (mdns.Registration, error) {
						calls++
						return mdns.Registration{}, nil
					},
					delete: func(context.Context, string) error { calls++; return nil },
				}
				r := httptest.NewRequest(method, "/v1/mdns/services/mlp", strings.NewReader(mlpJSON))
				r.Header.Set("Content-Type", "application/json")
				value := "https://example.test"
				if header == "Sec-Fetch-Site" {
					value = "cross-site"
				}
				r.Header.Set(header, value)
				w := httptest.NewRecorder()
				New(s).ServeHTTP(w, r)
				if w.Code != http.StatusForbidden || errorCode(t, w) != "CROSS_ORIGIN" || calls != 0 {
					t.Fatalf("cross-origin mutation: status=%d body=%s calls=%d", w.Code, w.Body.String(), calls)
				}
			})
		}
	}
}
