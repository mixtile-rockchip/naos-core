package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/hawkbit"
	"naos.local/core/internal/hostname"
	"naos.local/core/internal/identity"
	"naos.local/core/internal/oem"
)

func main() {
	runtime.GOMAXPROCS(1)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, stderr io.Writer) int {
	return runCommand(args, out, stderr)
}

func readOEM(cfg config.Config, out, stderr io.Writer) int {
	info, err := oem.Read(cfg.SoC)
	if err != nil {
		if errors.Is(err, oem.ErrUnsupported) {
			fmt.Fprintln(stderr, "naos-core: OEM is not supported; requires [platform] soc=rk3588")
		} else {
			fmt.Fprintln(stderr, "naos-core: read OEM OTP:", err)
		}
		return 1
	}
	sn, mac := info.Strings()
	fmt.Fprintf(out, "SN: %s\nMAC: %s\n", sn, mac)
	return 0
}

func checkHawkbit(cfg config.Config, path string, out, stderr io.Writer) int {
	if err := resolveControllerID(&cfg, path, ""); err != nil {
		_ = json.NewEncoder(out).Encode(hawkbit.CheckResult{ErrorCode: "IDENTITY", Error: "cannot read or persist the hawkBit controller ID"})
		return 1
	}
	result, err := hawkbit.Check(context.Background(), cfg.Hawkbit)
	if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
		fmt.Fprintln(stderr, "naos-core:", encodeErr)
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

func serve(cfg config.Config, path string, stderr io.Writer) int {
	syscall.Umask(0077)
	logger := log.New(stderr, "naos-core: ", log.LstdFlags)
	for _, warning := range cfg.Warnings {
		logger.Print(warning)
	}
	// Complete OEM/SN processing before any business-control endpoint exists.
	previousHostname, _ := os.Hostname()
	name, err := hostname.Apply(cfg.SoC)
	if err != nil {
		logger.Printf("OEM hostname: %v", err)
	}
	if name != "" && name != previousHostname {
		if err := syncAvahi(name); err != nil {
			logger.Printf("Avahi hostname: %v", err)
		}
	}
	if cfg.Hawkbit.Enabled {
		if err := resolveControllerID(&cfg, path, name); err != nil {
			logger.Printf("hawkBit identity: %v", err)
			return 1
		}
	}
	return runServices(cfg, path, logger, stderr)
}

func resolveControllerID(cfg *config.Config, path, sn string) error {
	if cfg.Hawkbit.ControllerID != "" {
		return nil
	}
	id, err := identity.Resolve(cfg.SoC, path, sn)
	if err == nil {
		cfg.Hawkbit.ControllerID = id
	}
	return err
}

func call(cfg config.Config, command string, args []string, requestID string, out, stderr io.Writer) int {
	method, path := http.MethodGet, "/v1/"+command
	var payload []byte
	if command == "reboot" || command == "recovery" {
		method = http.MethodPost
	}
	if command == "update" && len(args) == 1 {
		method = http.MethodPost
		payload, _ = json.Marshal(map[string]string{"path": args[0], "request_id": requestID})
	}
	if command == "tasks" {
		path = "/v1/update-tasks"
	}
	if command == "task" {
		path = "/v1/update-tasks/" + url.PathEscape(args[0])
	}
	if command == "containers" && len(args) == 2 {
		if args[0] != "start" && args[0] != "stop" && args[0] != "restart" {
			fmt.Fprintln(stderr, "naos-core: expected containers {start|stop|restart} ID")
			return 2
		}
		method, path = http.MethodPost, "/v1/containers/"+url.PathEscape(args[1])+"/"+args[0]
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", cfg.Socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequest(method, "http://localhost"+path, bytes.NewReader(payload))
	if err == nil && method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	var response *http.Response
	if err == nil {
		response, err = client.Do(request)
	}
	if err != nil {
		fmt.Fprintln(stderr, "naos-core:", err)
		return 1
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		fmt.Fprintln(stderr, "naos-core: cannot read bounded response", err)
		return 1
	}
	_, _ = out.Write(data)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 1
	}
	return 0
}
