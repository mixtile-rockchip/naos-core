package watchdog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

type managedMock struct {
	mu                          sync.Mutex
	requested                   int32
	effective                   int32
	feeds, disables, closes     int
	setErr, feedErr, disableErr error
	failFeed                    int
	feedEvents                  chan struct{}
}

func mockDevice() *managedMock {
	return &managedMock{effective: 44, feedEvents: make(chan struct{}, 16)}
}
func (d *managedMock) SetTimeout(request int32) (int32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requested = request
	return d.effective, d.setErr
}
func (d *managedMock) KeepAlive() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.feeds++
	if d.feeds == d.failFeed {
		return d.feedErr
	}
	d.feedEvents <- struct{}{}
	return nil
}
func (d *managedMock) StopUserAndClose() (CloseResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.disables++
	if d.disableErr != nil {
		return CloseResult{}, d.disableErr
	}
	d.closes++
	return CloseResult{FDClosed: true, UserWatchdogDisabled: true}, nil
}
func (d *managedMock) CloseWithoutStopping() (CloseResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closes++
	return CloseResult{FDClosed: true}, nil
}
func (d *managedMock) counts() (int, int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.feeds, d.disables, d.closes
}

func managerConfig() config.WatchdogConfig {
	return config.WatchdogConfig{Enabled: true, Device: "/dev/watchdog0", Timeout: 30 * time.Second, FeedInterval: 10 * time.Second}
}
func beginManager(t *testing.T, ctx context.Context, d *managedMock, health func(context.Context) error) (*Manager, chan time.Time) {
	t.Helper()
	ticks := make(chan time.Time, 16)
	m, err := startWith(ctx, managerConfig(), nil, health, func(string) (managedDevice, error) { return d, nil }, ticks)
	if err != nil {
		t.Fatal(err)
	}
	return m, ticks
}
func waitEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(time.Second):
		t.Fatal("expected watchdog operation did not complete")
	}
}
func waitFailure(t *testing.T, m *Manager) error {
	t.Helper()
	select {
	case err := <-m.Errors():
		if err == nil {
			t.Fatal("missing manager failure")
		}
		return err
	case <-time.After(time.Second):
		t.Fatal("watchdog failure was not observable")
	}
	return nil
}

func TestManagerSetsActualTimeoutFeedsAndStopsOnce(t *testing.T) {
	d := mockDevice()
	healthChecks := make(chan struct{}, 1)
	m, ticks := beginManager(t, context.Background(), d, func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			return errors.New("health timeout not bounded")
		}
		healthChecks <- struct{}{}
		return nil
	})
	if m.EffectiveTimeout() != 44*time.Second || d.requested != 30 {
		t.Fatal("quantized timeout was not preserved")
	}
	waitEvent(t, d.feedEvents)
	select {
	case <-healthChecks:
		t.Fatal("health checked before startup completed")
	default:
	}
	ticks <- time.Now()
	waitEvent(t, healthChecks)
	waitEvent(t, d.feedEvents)
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := m.Stop(); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if feeds, disables, closes := d.counts(); feeds != 2 || disables != 1 || closes != 1 {
		t.Fatalf("normal shutdown repeated device operations: %d %d %d", feeds, disables, closes)
	}
}

func TestManagerDisabledNeverOpensOrNeedsHealth(t *testing.T) {
	m, err := startWith(context.Background(), config.WatchdogConfig{}, nil, nil, func(string) (managedDevice, error) { t.Fatal("disabled watchdog opened"); return nil, nil }, nil)
	if err != nil || m.Errors() != nil || m.Stop() != nil {
		t.Fatal("disabled manager is not inert")
	}
}

func TestManagerValidatesBeforeOpen(t *testing.T) {
	for _, kind := range []string{"health", "timeout", "interval", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			cfg := managerConfig()
			health := func(context.Context) error { return nil }
			ctx := context.Background()
			switch kind {
			case "health":
				health = nil
			case "timeout":
				cfg.Timeout = 1500 * time.Millisecond
			case "interval":
				cfg.FeedInterval = cfg.Timeout
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			m, err := startWith(ctx, cfg, nil, health, func(string) (managedDevice, error) { t.Fatal("invalid manager reached open"); return nil, nil }, nil)
			if err == nil || m != nil {
				t.Fatal("invalid manager was started")
			}
		})
	}
}

func TestManagerHealthFailureDoesNotFeedOrDisable(t *testing.T) {
	d := mockDevice()
	broken := errors.New("Core not advancing")
	m, ticks := beginManager(t, context.Background(), d, func(context.Context) error { return broken })
	ticks <- time.Now()
	if err := waitFailure(t, m); !errors.Is(err, broken) {
		t.Fatal(err)
	}
	if err := m.Stop(); !errors.Is(err, broken) {
		t.Fatal("normal Stop hid a prior fault")
	}
	if feeds, disables, closes := d.counts(); feeds != 1 || disables != 0 || closes != 1 {
		t.Fatalf("health failure fed or disabled watchdog: %d %d %d", feeds, disables, closes)
	}
}

func TestManagerFeedFailureStopsWithoutRescue(t *testing.T) {
	d := mockDevice()
	broken := errors.New("ioctl failed")
	d.failFeed = 2
	d.feedErr = broken
	m, ticks := beginManager(t, context.Background(), d, func(context.Context) error { return nil })
	ticks <- time.Now()
	if err := waitFailure(t, m); !errors.Is(err, broken) {
		t.Fatal(err)
	}
	_ = m.Stop()
	if feeds, disables, closes := d.counts(); feeds != 2 || disables != 0 || closes != 1 {
		t.Fatalf("runtime failure attempted rescue or disable: %d %d %d", feeds, disables, closes)
	}
}

func TestManagerInitializationFailureNeverDisables(t *testing.T) {
	for _, kind := range []string{"set", "effective", "feed"} {
		t.Run(kind, func(t *testing.T) {
			d := mockDevice()
			switch kind {
			case "set":
				d.setErr = errors.New("set failed")
			case "effective":
				d.effective = 9
			case "feed":
				d.failFeed = 1
				d.feedErr = errors.New("first feed failed")
			}
			m, err := startWith(context.Background(), managerConfig(), nil, func(context.Context) error { return nil }, func(string) (managedDevice, error) { return d, nil }, nil)
			if err == nil || m != nil {
				t.Fatal("startup failure was hidden")
			}
			if _, disables, closes := d.counts(); disables != 0 || closes != 1 {
				t.Fatal("startup fault disabled watchdog or leaked ownership")
			}
		})
	}
}

func TestManagerStopFailureIsObservableAndReleasesOnce(t *testing.T) {
	d := mockDevice()
	d.disableErr = errors.New("nowayout")
	m, _ := beginManager(t, context.Background(), d, func(context.Context) error { return nil })
	if err := m.Stop(); !errors.Is(err, d.disableErr) {
		t.Fatal("disable failure was hidden")
	}
	if err := waitFailure(t, m); !errors.Is(err, d.disableErr) {
		t.Fatal(err)
	}
	_ = m.Stop()
	if _, disables, closes := d.counts(); disables != 1 || closes != 1 {
		t.Fatal("failed disable was retried or fd leaked")
	}
}

func TestManagerNormalCancellationDuringHealthDoesNotFeedAgain(t *testing.T) {
	d := mockDevice()
	entered := make(chan struct{})
	m, ticks := beginManager(t, context.Background(), d, func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() })
	ticks <- time.Now()
	waitEvent(t, entered)
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if feeds, disables, closes := d.counts(); feeds != 1 || disables != 1 || closes != 1 {
		t.Fatalf("cancel raced into another feed: %d %d %d", feeds, disables, closes)
	}
}

func TestManagerExpiredHealthCannotFeedEvenWithNilResult(t *testing.T) {
	d := mockDevice()
	m, ticks := beginManager(t, context.Background(), d, func(ctx context.Context) error { <-ctx.Done(); return nil })
	ticks <- time.Now()
	select {
	case err := <-m.Errors():
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("health deadline did not stop feeding")
	}
	_ = m.Stop()
	if feeds, disables, _ := d.counts(); feeds != 1 || disables != 0 {
		t.Fatal("late health success fed or disabled")
	}
}
