package hawkbit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"naos.local/core/internal/config"
)

type CheckResult struct {
	Valid        bool   `json:"valid"`
	HTTPStatus   int    `json:"http_status"`
	ServerURL    string `json:"server_url,omitempty"`
	ControllerID string `json:"controller_id,omitempty"`
	PollingSleep string `json:"polling_sleep,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// CheckError contains only a fixed classification and a safe description.
// Underlying URL/network errors and response bodies are deliberately omitted.
type CheckError struct {
	Code    string
	Message string
}

func (e *CheckError) Error() string { return e.Message }

// checkTransport remembers a transport error for classification only; poll
// deliberately discards its potentially sensitive URL text from public errors.
type checkTransport struct {
	base    *http.Transport
	lastErr error
}

func (t *checkTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	t.lastErr = err
	return response, err
}

// Check performs one authenticated base DDI GET using the supplied config,
// including when Enabled is false. It never writes an INI or starts an updater.
func Check(ctx context.Context, cfg config.HawkbitConfig) (CheckResult, error) {
	result := CheckResult{}
	fail := func(code, message string) (CheckResult, error) {
		result.ErrorCode, result.Error = code, message
		return result, &CheckError{Code: code, Message: message}
	}
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return fail("CONFIGURATION", "hawkBit server URL is not configured")
	}
	// Download/scheduler settings are irrelevant to a read-only token check.
	// Use their valid neutral defaults without changing the caller's config.
	cfg.PollInterval = time.Second
	cfg.DownloadPath = "/var/lib/naos-core/downloads"
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	origin, err := validate(cfg)
	if err != nil {
		return fail("CONFIGURATION", err.Error())
	}
	result.ServerURL = origin.Scheme + "://" + origin.Host
	result.ControllerID = cfg.ControllerID
	base := &http.Transport{MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1,
		ResponseHeaderTimeout: cfg.Timeout, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer base.CloseIdleConnections()
	transport := &checkTransport{base: base}
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	requestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	response, err := poll(requestCtx, client, origin, cfg)
	result.HTTPStatus = response.Status
	if err == nil {
		result.Valid, result.PollingSleep = true, response.Sleep.String()
		return result, nil
	}
	if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
		return fail("TIMEOUT", "hawkBit token check timed out")
	}
	if errors.Is(requestCtx.Err(), context.Canceled) {
		return fail("CANCELED", "hawkBit token check was canceled")
	}
	switch response.Status {
	case http.StatusUnauthorized:
		return fail("UNAUTHORIZED", "hawkBit rejected the token (HTTP 401)")
	case http.StatusForbidden:
		return fail("FORBIDDEN", "hawkBit denied this controller/token (HTTP 403)")
	}
	if response.Status >= 300 && response.Status < 400 {
		return fail("REDIRECT", "hawkBit redirected the request; redirects are not allowed")
	}
	if response.Status != 0 && response.Status != http.StatusOK {
		return fail("HTTP", fmt.Sprintf("hawkBit token check returned HTTP %d", response.Status))
	}
	if response.Status == http.StatusOK {
		return fail("RESPONSE", "hawkBit did not return a valid bounded DDI response")
	}
	var timeout net.Error
	if errors.As(transport.lastErr, &timeout) && timeout.Timeout() {
		return fail("TIMEOUT", "hawkBit token check timed out")
	}
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(transport.lastErr, &certificate) || errors.As(transport.lastErr, &authority) ||
		errors.As(transport.lastErr, &hostname) || errors.As(transport.lastErr, &invalid) ||
		(transport.lastErr != nil && strings.Contains(transport.lastErr.Error(), "tls:")) {
		return fail("TLS", "hawkBit TLS handshake or certificate verification failed")
	}
	return fail("NETWORK", "cannot connect to the configured hawkBit server")
}
