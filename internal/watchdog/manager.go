//go:build linux && (amd64 || arm64 || arm)

package watchdog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"naos.local/core/internal/config"
)

type Logger interface{ Printf(string, ...any) }

type managedDevice interface {
	SetTimeout(int32) (int32, error)
	KeepAlive() error
	StopUserAndClose() (CloseResult, error)
	CloseWithoutStopping() (CloseResult, error)
}

// Manager owns one watchdog. Its health callback must prove that Core itself
// can still advance; cloud, RAUC and business availability are not prerequisites.
type Manager struct {
	cancel    context.CancelFunc
	done      chan struct{}
	errors    chan error
	effective time.Duration
	err       error
}

func openManaged(path string) (managedDevice, error) {
	inspection, err := Inspect(path)
	if err != nil {
		return nil, err
	}
	device, err := Open(path, inspection.DeviceNumber)
	if err != nil {
		return nil, err
	}
	support, err := device.Support()
	if err == nil && (support.Identity != inspection.Identity || !support.CanSetTimeout || !support.CanKeepalive) {
		err = errors.New("watchdog identity or required ioctl support differs")
	}
	if err != nil {
		_, closeErr := device.CloseWithoutStopping()
		return nil, errors.Join(err, closeErr, errors.New("opened watchdog was released without disabling; hardware may remain armed"))
	}
	return device, nil
}

// Start sets the requested timeout, reads the driver's actual value and feeds
// once before returning. Every later tick requires a successful health check.
// Runtime failures stop feeding, never disable, and are published on Errors.
func Start(ctx context.Context, cfg config.WatchdogConfig, logger Logger, health func(context.Context) error) (*Manager, error) {
	return startWith(ctx, cfg, logger, health, openManaged, nil)
}

func startWith(ctx context.Context, cfg config.WatchdogConfig, logger Logger, health func(context.Context) error, open func(string) (managedDevice, error), ticks <-chan time.Time) (*Manager, error) {
	m := &Manager{done: make(chan struct{})}
	if !cfg.Enabled {
		close(m.done)
		return m, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if health == nil {
		return nil, errors.New("watchdog requires a Core health callback")
	}
	if cfg.Timeout < time.Second || cfg.Timeout > 5*time.Minute || cfg.Timeout%time.Second != 0 || cfg.FeedInterval < time.Second || cfg.FeedInterval >= cfg.Timeout {
		return nil, errors.New("invalid watchdog timeout or feed interval")
	}
	device, err := open(cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("open watchdog: %w", err)
	}
	fail := func(err error) (*Manager, error) {
		_, closeErr := device.CloseWithoutStopping()
		return nil, errors.Join(err, closeErr, errors.New("watchdog startup failed; released without disabling"))
	}
	effective, err := device.SetTimeout(int32(cfg.Timeout / time.Second))
	if err != nil {
		return fail(fmt.Errorf("set/read watchdog timeout: %w", err))
	}
	m.effective = time.Duration(effective) * time.Second
	if effective <= 0 || cfg.FeedInterval >= m.effective {
		return fail(errors.New("driver watchdog timeout is shorter than the feed interval"))
	}
	if err := device.KeepAlive(); err != nil {
		return fail(fmt.Errorf("initial watchdog feed: %w", err))
	}
	if logger != nil {
		logger.Printf("watchdog %s: requested %s, actual %s, feed every %s", cfg.Device, cfg.Timeout, m.effective, cfg.FeedInterval)
	}
	ctx, m.cancel = context.WithCancel(ctx)
	m.errors = make(chan error, 1)
	go func() {
		defer close(m.done)
		defer close(m.errors)
		if ticks == nil {
			ticker := time.NewTicker(cfg.FeedInterval)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			if ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
				continue
			case <-ticks:
				healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				err := health(healthCtx)
				if err == nil {
					err = healthCtx.Err()
				}
				cancel()
				if ctx.Err() != nil {
					continue
				}
				if err == nil {
					err = device.KeepAlive()
				}
				if err != nil {
					_, closeErr := device.CloseWithoutStopping()
					m.err = errors.Join(fmt.Errorf("watchdog health/feed failed: %w", err), closeErr)
					m.errors <- m.err
					return
				}
			}
		}
		result, err := device.StopUserAndClose()
		if err != nil && !result.FDClosed {
			_, closeErr := device.CloseWithoutStopping()
			err = errors.Join(err, closeErr, errors.New("watchdog could not be disabled; hardware may remain armed"))
		}
		if err != nil {
			m.err = fmt.Errorf("stop watchdog: %w", err)
			m.errors <- m.err
		}
	}()
	return m, nil
}

// Errors is nil when disabled. An enabled manager closes it after shutdown.
func (m *Manager) Errors() <-chan error            { return m.errors }
func (m *Manager) EffectiveTimeout() time.Duration { return m.effective }

// Stop is idempotent and may run concurrently. It only requests normal shutdown;
// a prior health/feed failure has already released ownership without disabling.
func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	<-m.done
	return m.err
}
