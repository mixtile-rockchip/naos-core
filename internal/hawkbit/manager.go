package hawkbit

import (
	"context"
	"errors"
	"log"
	"sync"

	"naos.local/core/internal/config"
)

var (
	ErrManagerNotRunning = errors.New("hawkBit manager is not running")
	ErrReloadBusy        = errors.New("hawkBit configuration change is pending")
)

type reloadRequest struct {
	ctx    context.Context
	next   *Runner
	result chan reloadResult
}

type reloadResult struct {
	applied, pending bool
	err              error
}

// Manager replaces immutable runners without restarting Core. A configuration
// change waits for an owned updater to finish; service shutdown still detaches
// that child in the same way as Runner.Run.
type Manager struct {
	mu       sync.Mutex
	current  *Runner
	hooks    Hooks
	logger   *log.Logger
	started  bool
	running  bool
	requests chan reloadRequest
	done     chan struct{}
}

func NewManager(cfg config.HawkbitConfig, hooks Hooks, logger *log.Logger) (*Manager, error) {
	runner, err := New(cfg, hooks, logger)
	if err != nil {
		return nil, err
	}
	return &Manager{current: runner, hooks: hooks, logger: logger,
		requests: make(chan reloadRequest), done: make(chan struct{})}, nil
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	runner := m.current
	m.mu.Unlock()
	return runner.Snapshot()
}

// Reload validates before touching the current runner. Once a pending change
// is accepted, it belongs to the manager lifetime, not this request's context.
func (m *Manager) Reload(ctx context.Context, cfg config.HawkbitConfig) (applied, pending bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	next, err := New(cfg, m.hooks, m.logger)
	if err != nil {
		return false, false, err
	}
	m.mu.Lock()
	running := m.running
	next.options = m.current.options
	m.mu.Unlock()
	if !running {
		return false, false, ErrManagerNotRunning
	}
	request := reloadRequest{ctx: ctx, next: next, result: make(chan reloadResult, 1)}
	select {
	case <-ctx.Done():
		return false, false, ctx.Err()
	case <-m.done:
		return false, false, ErrManagerNotRunning
	case m.requests <- request:
	}
	select {
	case result := <-request.result:
		return result.applied, result.pending, result.err
	case <-ctx.Done():
		return false, false, ctx.Err()
	case <-m.done:
		return false, false, ErrManagerNotRunning
	}
}

// Run remains available for Reload even when the initial runner is disabled or
// has failed. Only this context stops the manager and its current runner.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("hawkBit manager has already run")
	}
	m.started, m.running = true, true
	current := m.current
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		close(m.done)
	}()

	var cancel context.CancelFunc
	var done chan error
	start := func(runner *Runner) {
		var child context.Context
		child, cancel = context.WithCancel(ctx)
		done = make(chan error, 1)
		finished := done
		go func() { finished <- runner.Run(child) }()
	}
	logFailure := func(err error) {
		if err != nil && m.logger != nil {
			m.logger.Printf("hawkBit stopped: %v", err)
		}
	}
	stop := func() {
		cancel()
		if done != nil {
			logFailure(<-done)
			done = nil
		}
	}
	start(current)
	defer stop()
	apply := func(next *Runner) error {
		stop()
		if err := ctx.Err(); err != nil {
			return err
		}
		current = next
		m.mu.Lock()
		m.current = next
		m.mu.Unlock()
		start(next)
		return nil
	}

	var pending *Runner
	var drained <-chan struct{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			logFailure(err)
			done = nil
		case <-drained:
			if err := apply(pending); err != nil {
				return nil // The parent stopped while the old runner drained.
			}
			pending, drained = nil, nil
		case request := <-m.requests:
			if err := ctx.Err(); err != nil {
				request.result <- reloadResult{err: err}
				return nil
			}
			if err := request.ctx.Err(); err != nil {
				request.result <- reloadResult{err: err}
				continue
			}
			if pending != nil {
				request.result <- reloadResult{err: ErrReloadBusy}
				continue
			}
			active, ready := current.drain()
			if active {
				pending, drained = request.next, ready
				request.result <- reloadResult{pending: true}
				continue
			}
			err := apply(request.next)
			request.result <- reloadResult{applied: err == nil, err: err}
		}
	}
}
