package main

import (
	"context"
	"log"
	"time"

	"naos.local/core/internal/operation"
	"naos.local/core/internal/update"
)

type autoRebootUpdates interface {
	PrepareAutoReboot(context.Context, string) (update.Task, *operation.Lease, error)
}

// Use the same operation gate and normal system reboot as explicit requests.
// A failed command is tried only once per task in this Core process.
func autoReboot(ctx context.Context, updates autoRebootUpdates, reboot func() error, logger *log.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	runAutoReboot(ctx, updates, reboot, logger, ticker.C)
}

func runAutoReboot(ctx context.Context, updates autoRebootUpdates, reboot func() error, logger *log.Logger, ticks <-chan time.Time) {
	attemptedID, lastError := "", ""
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
		}
		if ctx.Err() != nil {
			return
		}
		task, lease, err := updates.PrepareAutoReboot(ctx, attemptedID)
		if err != nil {
			lease.Release()
			if message := err.Error(); message != lastError {
				logger.Printf("automatic update reboot deferred: %v", err)
				lastError = message
			}
			continue
		}
		lastError = ""
		if lease == nil {
			continue
		}
		if ctx.Err() != nil {
			lease.Release()
			return
		}
		attemptedID = task.ID
		logger.Printf("update task %s (%s, version %s) installed; rebooting into %s", task.ID, task.Source, task.Version, task.TargetSlot)
		if err := reboot(); err != nil {
			logger.Printf("automatic reboot for update task %s failed: %v", task.ID, err)
			lease.Release()
			continue
		}
		// A successful /sbin/reboot requests OpenRC shutdown asynchronously.
		// Keep admission closed while the system is still running.
		return
	}
}
