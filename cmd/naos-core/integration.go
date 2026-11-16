package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/container"
	"naos.local/core/internal/hawkbit"
	"naos.local/core/internal/httpapi"
	"naos.local/core/internal/mdns"
	"naos.local/core/internal/oem"
	"naos.local/core/internal/operation"
	"naos.local/core/internal/recovery"
	"naos.local/core/internal/server"
	"naos.local/core/internal/update"
	"naos.local/core/internal/watchdog"
)

// Called after SN/hostname initialization, before Core can explicitly deploy
// containers. OpenRC/naosd retain their existing automatic-start behavior.
func runServices(cfg config.Config, path string, logger *log.Logger, stderr io.Writer) int {
	configPath, err := filepath.Abs(path)
	if err != nil {
		logger.Print("cannot resolve Core configuration path")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// Keep HTTP alive until a normal stop has relinquished watchdog ownership.
	work, stop := context.WithCancel(context.Background())
	defer stop()
	gate := operation.New()
	updates, err := update.NewPersistent(cfg.StateDir, gate)
	if err != nil {
		logger.Printf("update task storage: %v", err)
		return 1
	}
	defer updates.Close()
	cloud, err := hawkbit.NewManager(cfg.Hawkbit, hawkbit.Hooks{
		BeginExternal: func(ctx context.Context, request hawkbit.ExternalRequest) (string, error) {
			task, err := updates.BeginExternal(ctx, update.ExternalRequest{Source: "hawkbit", RequestID: request.RequestID, Path: request.Path, ActionID: request.ActionID, Version: request.Version})
			return task.ID, err
		},
		AttachExternal: func(ctx context.Context, id string, p hawkbit.ProcessIdentity) error {
			return updates.AttachExternal(ctx, id, update.ExternalIdentity{PID: p.PID, StartTime: p.StartTime, BootID: p.BootID, Exe: p.Exe, ConfigPath: p.ConfigPath, ConfigSHA256: p.ConfigSHA256})
		},
		EndExternal: func(ctx context.Context, id string, code int, runErr error) error {
			_, err := updates.EndExternal(ctx, id, code, runErr)
			return err
		},
	}, logger)
	if err != nil {
		logger.Print(err)
		return 1
	}
	discovery := mdns.New()
	defer discovery.Close()
	containers := container.Client{Socket: cfg.ContainerSocket}
	reboot := func() error {
		cmd := exec.Command("/sbin/reboot")
		cmd.Stdout, cmd.Stderr = stderr, stderr
		return cmd.Run()
	}
	handler := httpapi.New(httpapi.Services{
		MDNS: discovery, OEM: func() (oem.Info, error) { return oem.Read(cfg.SoC) },
		Containers: containers.List, ContainerChange: containers.Change,
		Update: updates.Install, InstallTask: updates.InstallRequest,
		UpdateStatus: updates.Status, Tasks: updates.Tasks, Task: updates.Task, Busy: updates.Busy,
		Recovery: recovery.Request, Gate: gate, HawkbitStatus: func() any { return cloud.Snapshot() },
		HawkbitReload: func(ctx context.Context, requestedPath string) (bool, bool, error) {
			if requestedPath != configPath {
				return false, false, errors.New("registration uses a different Core configuration")
			}
			next, err := config.Load(configPath)
			if err != nil || !next.Hawkbit.Enabled || next.Hawkbit.ControllerID == "" {
				return false, false, errors.New("invalid saved hawkBit registration")
			}
			return cloud.Reload(ctx, next.Hawkbit)
		},
		Reboot: reboot, Log: logger,
	})
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Run(work, cfg, handler) }()
	go func() {
		if err := cloud.Run(ctx); err != nil {
			logger.Printf("hawkBit stopped: %v", err)
		}
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", cfg.Socket)
	}, MaxIdleConns: 1, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	health := func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/healthz", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 256))
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("Core health status %d", response.StatusCode)
		}
		return nil
	}
	// Do not derive the watchdog's context from work: a fatal service error
	// must leave it armed, while a normal TERM explicitly calls Stop below.
	dog, err := watchdog.Start(context.Background(), cfg.Watchdog, logger, health)
	if err != nil {
		logger.Print(err)
		return 1
	}
	startupDone := make(chan struct{})
	go func() {
		defer close(startupDone)
		if err := startConfiguredContainer(ctx, cfg, containers, logger); err != nil && ctx.Err() == nil {
			logger.Printf("container startup: %v", err)
		}
	}()
	autoDone := make(chan struct{})
	go func() {
		defer close(autoDone)
		autoReboot(ctx, updates, reboot, logger)
	}()
	defer func() {
		cancel()
		<-autoDone
		<-startupDone
	}()
	httpEndpoint := "disabled"
	if cfg.HTTPEnabled {
		httpEndpoint = cfg.HTTPListen
	}
	logger.Printf("serving Unix socket %s; TCP HTTP listener: %s; startup confirmation remains naos-boot-confirm", cfg.Socket, httpEndpoint)
	select {
	case <-ctx.Done():
		if err := dog.Stop(); err != nil {
			logger.Print(err)
			return 1
		}
		stop()
		select {
		case err := <-serverResult:
			if err != nil {
				logger.Print(err)
				return 1
			}
		case <-time.After(6 * time.Second):
			logger.Print("HTTP shutdown timed out")
			return 1
		}
		return 0
	case err := <-serverResult:
		if ctx.Err() != nil {
			_ = dog.Stop()
			return 0
		}
		logger.Printf("Core HTTP service stopped: %v", err)
		return 1
	case err := <-dog.Errors():
		logger.Printf("watchdog failure: %v", err)
		return 1
	}
}
