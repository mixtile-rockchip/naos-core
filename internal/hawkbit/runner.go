package hawkbit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"naos.local/core/internal/config"
)

type ExternalRequest struct{ RequestID, Path, ActionID, Version string }
type Hooks struct {
	BeginExternal  func(context.Context, ExternalRequest) (string, error)
	AttachExternal func(context.Context, string, ProcessIdentity) error
	EndExternal    func(context.Context, string, int, error) error
}
type HeartbeatSnapshot struct {
	LastSuccess  time.Time `json:"last_success,omitempty"`
	NextPoll     time.Time `json:"next_poll,omitempty"`
	HTTPStatus   int       `json:"http_status"`
	PollingSleep string    `json:"polling_sleep,omitempty"`
	Action       string    `json:"action,omitempty"`
	Error        string    `json:"error,omitempty"`
}
type UpdaterSnapshot struct {
	Phase           string    `json:"phase"`
	TaskID          string    `json:"task_id,omitempty"`
	PID             int       `json:"pid,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	CompletedAt     time.Time `json:"completed_at,omitempty"`
	NextRun         time.Time `json:"next_run,omitempty"`
	ExitCode        *int      `json:"exit_code"`
	DownloadPercent *int      `json:"download_percent"`
	Error           string    `json:"error,omitempty"`
}
type Snapshot struct {
	Enabled         bool              `json:"enabled"`
	State           string            `json:"state"`
	Heartbeat       HeartbeatSnapshot `json:"heartbeat"`
	Updater         UpdaterSnapshot   `json:"updater"`
	RecentLogs      []string          `json:"recent_logs"`
	SystemVersion   string            `json:"system_version,omitempty"`
	AttributesError string            `json:"attributes_error,omitempty"`
}
type runnerOptions struct {
	directory, updater         string
	versionFile, osReleaseFile string
	monitorInterval            time.Duration
	childEnv                   []string
}
type Runner struct {
	cfg        config.HawkbitConfig
	origin     *url.URL
	client     *http.Client
	transport  *http.Transport
	hooks      Hooks
	logger     *log.Logger
	options    runnerOptions
	mu         sync.Mutex
	snapshot   Snapshot
	running    bool
	draining   bool
	scheduling bool
	drained    chan struct{}
}

func New(cfg config.HawkbitConfig, hooks Hooks, logger *log.Logger) (*Runner, error) {
	r := &Runner{cfg: cfg, hooks: hooks, logger: logger, options: runnerOptions{directory: runtimeDir, updater: updaterBinary, monitorInterval: 500 * time.Millisecond}, snapshot: Snapshot{Enabled: cfg.Enabled, State: "disabled", Updater: UpdaterSnapshot{Phase: "disabled"}, RecentLogs: []string{}}}
	r.options.versionFile = "/usr/lib/naos/version.json"
	r.options.osReleaseFile = "/etc/os-release"
	r.drained = make(chan struct{})
	if !cfg.Enabled {
		return r, nil
	}
	origin, err := validate(cfg)
	if err != nil {
		return nil, err
	}
	if hooks.BeginExternal == nil || hooks.AttachExternal == nil || hooks.EndExternal == nil {
		return nil, errors.New("hawkBit requires coordinated update hooks")
	}
	r.origin = origin
	r.transport = &http.Transport{MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 65 * time.Second, ResponseHeaderTimeout: cfg.Timeout}
	r.client = &http.Client{Transport: r.transport, Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r.snapshot.State = "stopped"
	r.snapshot.Updater.Phase = "idle"
	return r, nil
}
func (r *Runner) change(fn func(*Snapshot)) { r.mu.Lock(); defer r.mu.Unlock(); fn(&r.snapshot) }

// drain prevents another runOnce from starting, but lets its current owner
// finish the updater and EndExternal before a manager replaces this runner.
func (r *Runner) drain() (bool, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.draining {
		r.draining = true
		if !r.scheduling {
			close(r.drained)
		}
	}
	return r.scheduling, r.drained
}

func (r *Runner) beginScheduledRun(ctx context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining || ctx.Err() != nil {
		return false
	}
	r.scheduling = true
	return true
}

func (r *Runner) endScheduledRun() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scheduling = false
	if r.draining {
		close(r.drained)
	}
}

func (r *Runner) Snapshot() Snapshot {
	r.mu.Lock()
	s := r.snapshot
	if s.Updater.ExitCode != nil {
		code := *s.Updater.ExitCode
		s.Updater.ExitCode = &code
	}
	r.mu.Unlock()
	if r.cfg.Enabled {
		s.RecentLogs = r.recentLogs()
	}
	return s
}
func (r *Runner) recentLogs() []string {
	f, err := os.OpenFile(logPath(r.options.directory), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return []string{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return []string{}
	}
	start := max(int64(0), info.Size()-4096)
	if _, err = f.Seek(start, io.SeekStart); err != nil {
		return []string{}
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return []string{}
	}
	text := string(data)
	if r.cfg.Token != "" {
		text = strings.ReplaceAll(text, r.cfg.Token, "[redacted]")
	}
	// The INI may still belong to a previous run; use its token for redaction
	// only, without reconstructing that run or resuming its state.
	if configuration, err := readPrivate(configPath(r.options.directory), 8192); err == nil {
		for _, line := range strings.Split(string(configuration), "\n") {
			key, token, ok := strings.Cut(line, "=")
			if ok && (key == "auth_token" || key == "gateway_token") && token != "" {
				text = strings.ReplaceAll(text, token, "[redacted]")
			}
		}
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if start > 0 {
		lines = lines[1:]
	}
	if len(lines) > 16 {
		lines = lines[len(lines)-16:]
	}
	for i, line := range lines {
		line = strings.Map(func(c rune) rune {
			if c < 32 && c != '\t' {
				return -1
			}
			return c
		}, line)
		if len(line) > 256 {
			line = line[:256]
		}
		lines[i] = line
	}
	return lines
}
func (r *Runner) Run(ctx context.Context) (runErr error) {
	if !r.cfg.Enabled {
		return nil
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("hawkBit runner is already running")
	}
	r.running = true
	r.snapshot.State = "starting"
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.running = false
		r.snapshot.State = "stopped"
		if runErr != nil {
			r.snapshot.State = "failed"
		}
	}()
	if err := privateDir(r.options.directory); err != nil {
		return err
	}
	if err := privateDir(r.cfg.DownloadPath); err != nil {
		return err
	}
	lock, err := lockFile(filepath.Join(r.options.directory, "hawkbit-controller.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	defer r.transport.CloseIdleConnections()
	r.change(func(s *Snapshot) { s.State = "running" })
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); r.heartbeat(ctx) }()
	go func() { defer workers.Done(); r.scheduler(ctx) }()
	workers.Wait()
	return nil
}
func wait(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func backoff(base time.Duration, failures int) time.Duration {
	for i := 1; i < failures && i < 8 && base < 24*time.Hour; i++ {
		base *= 2
	}
	return min(base, 24*time.Hour)
}
func (r *Runner) heartbeat(ctx context.Context) {
	delay, failures := time.Duration(0), 0
	lastAttributes := ""
	for wait(ctx, delay) {
		result, err := poll(ctx, r.client, r.origin, r.cfg)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			delay = backoff(min(r.cfg.PollInterval, 30*time.Second), failures)
		} else {
			failures = 0
			delay = result.Sleep
		}
		r.change(func(s *Snapshot) {
			s.Heartbeat.HTTPStatus, s.Heartbeat.NextPoll = result.Status, time.Now().UTC().Add(delay)
			if err != nil {
				s.Heartbeat.Error = err.Error()
			} else {
				s.Heartbeat.LastSuccess, s.Heartbeat.Error = time.Now().UTC(), ""
				s.Heartbeat.PollingSleep, s.Heartbeat.Action = result.Sleep.String(), result.Action
			}
		})
		if err == nil {
			attributes, attributeErr := readSystemAttributes(r.options.versionFile, r.options.osReleaseFile)
			if attributeErr == nil {
				encoded, encodeErr := json.Marshal(attributes)
				attributeErr = encodeErr
				if attributeErr == nil && len(attributes) > 0 && (string(encoded) != lastAttributes || result.ConfigData) {
					attributeErr = reportAttributes(ctx, r.client, r.origin, r.cfg, attributes)
					if attributeErr == nil {
						lastAttributes = string(encoded)
					}
				}
				r.change(func(s *Snapshot) { s.SystemVersion = attributes["system_version"] })
			}
			if ctx.Err() != nil {
				return
			}
			r.change(func(s *Snapshot) {
				s.AttributesError = ""
				if attributeErr != nil {
					s.AttributesError = attributeErr.Error()
				}
			})
		}
	}
}
func (r *Runner) scheduler(ctx context.Context) {
	delay, failures := time.Duration(0), 0
	for wait(ctx, delay) {
		active, err := hasRunningUpdater(r.options.updater)
		if err != nil {
			failures++
			delay = backoff(r.cfg.PollInterval, failures)
			r.change(func(s *Snapshot) {
				s.Updater.Phase, s.Updater.Error = "blocked", "cannot inspect running updater processes"
			})
		} else if active {
			delay = r.cfg.PollInterval
			r.change(func(s *Snapshot) {
				s.Updater = UpdaterSnapshot{Phase: "skipped", Error: "updater already running; skipping this interval"}
			})
		} else {
			if !r.beginScheduledRun(ctx) {
				return
			}
			err = r.runOnce(ctx)
			r.endScheduledRun()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				failures++
			} else {
				failures = 0
			}
			delay = backoff(r.cfg.PollInterval, failures)
		}
		r.change(func(s *Snapshot) { s.Updater.NextRun = time.Now().UTC().Add(delay) })
	}
}
func (r *Runner) runOnce(ctx context.Context) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	request := ExternalRequest{RequestID: "hawkbit-" + hex.EncodeToString(nonce[:]), Path: filepath.Join(r.cfg.DownloadPath, "hawkbit.raucb")}
	callCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	id, err := r.hooks.BeginExternal(callCtx, request)
	cancel()
	if err != nil || id == "" {
		r.change(func(s *Snapshot) {
			s.Updater.Phase, s.Updater.Error = "deferred", "update operation is busy or unavailable"
		})
		return errors.New("cannot reserve updater operation")
	}
	started := time.Now().UTC()
	r.change(func(s *Snapshot) { s.Updater = UpdaterSnapshot{Phase: "starting", TaskID: id, StartedAt: started} })
	finish := func(code int, runErr error) error {
		callCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
		defer cancel()
		endErr := r.hooks.EndExternal(callCtx, id, code, runErr)
		r.change(func(s *Snapshot) {
			s.Updater.Phase, s.Updater.CompletedAt, s.Updater.ExitCode = "completed", time.Now().UTC(), &code
			if runErr != nil {
				s.Updater.Error = "updater process failed"
			}
			if endErr != nil {
				s.Updater.Error = "updater task completion requires inspection"
			}
		})
		if endErr != nil {
			return endErr
		}
		return runErr
	}
	output, err := openLog(logPath(r.options.directory))
	if err != nil {
		return finish(-1, err)
	}
	defer output.Close()
	// Start a fresh current log before changing the INI/token. Older private
	// logs remain in .1 but cannot leak through a new run's public snapshot.
	if err := rotateLogForRun(output, logPath(r.options.directory)); err != nil {
		return finish(-1, errors.New("cannot rotate updater log"))
	}
	configuration := ini(r.cfg, r.origin)
	if atomicWrite(configPath(r.options.directory), configuration) != nil {
		return finish(-1, errors.New("cannot publish updater configuration"))
	}
	cmd := exec.Command(r.options.updater, "--config-file", configPath(r.options.directory), "--run-once")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = output, output
	if r.options.childEnv != nil {
		cmd.Env = r.options.childEnv
	}
	if err := cmd.Start(); err != nil {
		return finish(-1, errors.New("cannot start updater"))
	}
	r.change(func(s *Snapshot) { s.Updater.Phase, s.Updater.PID = "running", cmd.Process.Pid })
	if identity, err := processIdentity(cmd.Process.Pid); err == nil {
		identity.ConfigPath, identity.ConfigSHA256 = configPath(r.options.directory), hash(configuration)
		callCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
		err = r.hooks.AttachExternal(callCtx, id, identity)
		cancel()
		if err != nil {
			r.change(func(s *Snapshot) { s.Updater.Error = "cannot attach updater process to task" })
		}
	}
	// Wait reaps only this child. Cancellation returns immediately, without
	// killing it or retaining a parent-owned output pipe. A later Core only
	// scans/skips it; its old exit status is not reconstructed.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(r.options.monitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.change(func(s *Snapshot) { s.Updater.Phase = "detached" })
			return ctx.Err()
		case <-ticker.C:
			if rotateLog(output, logPath(r.options.directory)) != nil {
				r.change(func(s *Snapshot) { s.Updater.Error = "cannot rotate updater log" })
			}
		case waitErr := <-done:
			code := 0
			if waitErr != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(waitErr, &exit) {
					code = exit.ExitCode()
				}
			}
			_ = rotateLog(output, logPath(r.options.directory))
			if waitErr != nil {
				return finish(code, errors.New("updater process failed"))
			}
			return finish(code, nil)
		}
	}
}
