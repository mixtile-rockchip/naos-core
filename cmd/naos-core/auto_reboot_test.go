package main

import (
	"context"
	"errors"
	"io"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"naos.local/core/internal/operation"
	"naos.local/core/internal/update"
)

type prepareRebootFunc func(context.Context, string) (update.Task, *operation.Lease, error)

func (f prepareRebootFunc) PrepareAutoReboot(ctx context.Context, attempted string) (update.Task, *operation.Lease, error) {
	return f(ctx, attempted)
}

func waitAutoReboot(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("automatic reboot coordinator did not finish")
	}
}

func TestAutoRebootKeepsAdmissionClosedDuringShutdown(t *testing.T) {
	for _, source := range []string{"local", "hawkbit"} {
		t.Run(source, func(t *testing.T) {
			gate := operation.New()
			updates := prepareRebootFunc(func(ctx context.Context, attempted string) (update.Task, *operation.Lease, error) {
				if attempted != "" {
					t.Errorf("first attempt unexpectedly excluded %s", attempted)
				}
				lease, err := gate.TryAcquire("update-reboot")
				return update.Task{ID: "new-install", Source: source}, lease, err
			})
			var calls int
			reboot := func() error {
				calls++
				if !gate.Busy() {
					t.Error("reboot was called without holding admission")
				}
				return nil
			}
			ticks := make(chan time.Time, 2)
			ticks <- time.Now()
			ticks <- time.Now()
			close(ticks)
			runAutoReboot(context.Background(), updates, reboot, log.New(io.Discard, "", 0), ticks)
			if calls != 1 || !gate.Busy() {
				t.Fatalf("reboot calls=%d, admission closed=%v", calls, gate.Busy())
			}
			if _, err := gate.TryAcquire("recovery"); !errors.Is(err, operation.ErrBusy) {
				t.Fatalf("shutdown allowed another operation: %v", err)
			}
		})
	}
}

func TestAutoRebootCommandFailureAllowsNewTaskWithoutRetryingOldTask(t *testing.T) {
	gate := operation.New()
	var latest atomic.Value
	latest.Store("first")
	prepared, rebooted := make(chan string, 4), make(chan string, 2)
	updates := prepareRebootFunc(func(ctx context.Context, attempted string) (update.Task, *operation.Lease, error) {
		id := latest.Load().(string)
		if attempted == id {
			prepared <- "excluded:" + id
			return update.Task{}, nil, nil
		}
		lease, err := gate.TryAcquire("update-reboot")
		prepared <- id
		return update.Task{ID: id}, lease, err
	})
	firstFinished := make(chan struct{})
	reboot := func() error {
		id := latest.Load().(string)
		rebooted <- id
		if id == "first" {
			defer close(firstFinished)
			return errors.New("injected reboot failure")
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks, done := make(chan time.Time), make(chan struct{})
	go func() {
		defer close(done)
		runAutoReboot(ctx, updates, reboot, log.New(io.Discard, "", 0), ticks)
	}()
	ticks <- time.Now()
	if id := <-rebooted; id != "first" {
		t.Fatalf("unexpected first reboot: %s", id)
	}
	waitAutoReboot(t, firstFinished)
	ticks <- time.Now()
	if id := <-prepared; id != "first" {
		t.Fatalf("unexpected prepared task: %s", id)
	}
	if id := <-prepared; id != "excluded:first" || gate.Busy() {
		t.Fatalf("failed task was retried or admission retained: %s, busy=%v", id, gate.Busy())
	}
	latest.Store("second")
	ticks <- time.Now()
	if id := <-rebooted; id != "second" {
		t.Fatalf("new task did not request its own reboot: %s", id)
	}
	waitAutoReboot(t, done)
	if !gate.Busy() {
		t.Fatal("new successful reboot lost its lease")
	}
}

func TestAutoRebootWaitsForAuthorizationAndRecoversFromReadError(t *testing.T) {
	gate := operation.New()
	var prepares, reboots int
	updates := prepareRebootFunc(func(context.Context, string) (update.Task, *operation.Lease, error) {
		prepares++
		switch prepares {
		case 1:
			return update.Task{}, nil, errors.New("RAUC unavailable")
		case 2:
			return update.Task{}, nil, nil
		default:
			lease, err := gate.TryAcquire("update-reboot")
			return update.Task{ID: "verified"}, lease, err
		}
	})
	ticks := make(chan time.Time, 3)
	for i := 0; i < 3; i++ {
		ticks <- time.Now()
	}
	close(ticks)
	runAutoReboot(context.Background(), updates, func() error {
		if prepares != 3 {
			t.Errorf("reboot before complete authorization: %d", prepares)
		}
		reboots++
		return nil
	}, log.New(io.Discard, "", 0), ticks)
	if reboots != 1 {
		t.Fatalf("reboot calls=%d", reboots)
	}
}

func TestAutoRebootCancellationReleasesPreparedLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate := operation.New()
	updates := prepareRebootFunc(func(context.Context, string) (update.Task, *operation.Lease, error) {
		lease, err := gate.TryAcquire("update-reboot")
		cancel()
		return update.Task{ID: "verified"}, lease, err
	})
	ticks := make(chan time.Time, 1)
	ticks <- time.Now()
	close(ticks)
	runAutoReboot(ctx, updates, func() error {
		t.Error("stopping Core initiated a new reboot")
		return nil
	}, log.New(io.Discard, "", 0), ticks)
	if gate.Busy() {
		t.Fatal("cancelled reboot retained admission")
	}
}
