package hawkbit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestManualRegistrationRejectsTargetAuthentication(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	cfg := fixtureConfig(t, server.URL)
	cfg.TokenType = "target"
	result, err := Register(context.Background(), cfg)
	if err == nil || result.Registered || result.ErrorCode != "CONFIGURATION" || calls.Load() != 0 || strings.Contains(err.Error(), cfg.Token) {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, calls.Load())
	}
}
