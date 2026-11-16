package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/hawkbit"
	"naos.local/core/internal/identity"
)

type registrationOptions struct{ server, tenant, token string }

type registrationResponse struct {
	hawkbit.RegisterResult
	Saved          bool `json:"saved"`
	Applied        bool `json:"applied"`
	Pending        bool `json:"pending"`
	ServiceRunning bool `json:"service_running"`
}

func register(options registrationOptions, path string, out, stderr io.Writer) int {
	// Inputs come only from command arguments and live hardware, never the INI.
	if strings.TrimSpace(options.server) == "" || strings.TrimSpace(options.tenant) == "" || strings.TrimSpace(options.token) == "" {
		fmt.Fprintln(stderr, "naos-core: register requires --server, --tenant and --token (GatewayToken)")
		printHelp(stderr, "hawkbit")
		return 2
	}
	response := registrationResponse{}
	finish := func(code int) int {
		if err := json.NewEncoder(out).Encode(response); err != nil {
			fmt.Fprintln(stderr, "naos-core: cannot write registration result")
			return 1
		}
		return code
	}
	id, err := identity.Generate()
	if err != nil {
		response.ErrorCode, response.Error = "IDENTITY", "cannot generate the hawkBit controller ID"
		return finish(1)
	}
	profile := config.HawkbitConfig{ServerURL: options.server, Tenant: options.tenant,
		Token: options.token, TokenType: "gateway", ControllerID: id, Timeout: 30 * time.Second}
	response.RegisterResult, err = hawkbit.Register(context.Background(), profile)
	if err != nil {
		return finish(1)
	}
	if err := config.SaveHawkbitRegistration(path, profile); err != nil {
		// The remote registration succeeded; local persistence is independent.
		response.ErrorCode, response.Error = "PERSISTENCE", "device registered, but its configuration could not be saved"
		return finish(1)
	}
	response.Saved = true
	response.Applied, response.Pending, response.ServiceRunning, err = applyRegistration(path)
	if err != nil {
		response.ErrorCode, response.Error = "APPLY", "device registered and configuration saved, but the running Core could not apply it"
		return finish(1)
	}
	return finish(0)
}

// Only the destination socket is read after registration has succeeded. The
// daemon loads its own INI; credentials are never sent through this endpoint.
func applyRegistration(path string) (applied, pending, running bool, err error) {
	cfg, err := config.Load(path)
	if err != nil || !cfg.Hawkbit.Enabled {
		return false, false, false, errors.New("cannot load saved registration")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return false, false, false, err
	}
	payload, err := json.Marshal(struct {
		Path string `json:"config_path"`
	}{path})
	if err != nil {
		return false, false, false, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.Socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodPost, "http://localhost/v1/hawkbit/reload", bytes.NewReader(payload))
	if err != nil {
		return false, false, false, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			// A deliberately stopped Core will use the saved profile at startup.
			return false, false, false, nil
		}
		return false, false, true, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return false, false, true, errors.New("Core rejected registration reload")
	}
	var result struct {
		Applied bool `json:"applied"`
		Pending bool `json:"pending"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return false, false, true, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, false, true, errors.New("invalid Core reload response")
	}
	if result.Applied == result.Pending || (response.StatusCode == http.StatusOK) != result.Applied {
		return false, false, true, errors.New("inconsistent Core reload response")
	}
	return result.Applied, result.Pending, true, nil
}
