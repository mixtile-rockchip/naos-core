package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/container"
)

type startupContainerClient interface {
	List(context.Context) ([]container.State, error)
	StartManifest(context.Context, string) error
}

// SN/hostname initialization has completed before runServices reaches this.
// Business startup is independent of Core's HTTP and watchdog readiness.
func startConfiguredContainer(ctx context.Context, cfg config.Config, client startupContainerClient, logger *log.Logger) error {
	if !cfg.ContainerEnabled {
		return nil
	}
	// OpenRC orders the daemons, but naosd's socket may still be starting.
	ready, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := ready.Err(); err != nil {
			return fmt.Errorf("wait for naosd: %w", err)
		}
		if _, err := client.List(ready); err == nil {
			break
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ready.Done():
			timer.Stop()
			return fmt.Errorf("wait for naosd: %w", ready.Err())
		case <-timer.C:
		}
	}
	// A timeout/disconnect can follow a successful start, so send only once.
	if err := client.StartManifest(ctx, cfg.ContainerManifest); err != nil {
		return fmt.Errorf("start configured container: %w", err)
	}
	logger.Printf("container started from %s", cfg.ContainerManifest)
	return nil
}
