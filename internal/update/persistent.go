package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"naos.local/core/internal/operation"
)

type tracker struct {
	store            *taskStore
	tasks            []Task
	external         *Task
	lastEmpty        *Task
	gate             *operation.Gate
	lease            *operation.Lease
	active           string
	bootID           string
	cancel           context.CancelFunc
	done             chan struct{}
	wake             chan struct{}
	lastProgress     time.Time
	unavailableSince time.Time
	processScan      func() (bool, bool)
	bootConfirmed    func() bool
	runningVersion   func() string
	saveError        error
}

// NewPersistent starts one bounded observer. It never replays InstallBundle on
// loading a journal; only RAUC's signed installation records can recover it.
func NewPersistent(stateDir string, gate *operation.Gate) (*Client, error) {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	c := New()
	if err := c.initPersistent(stateDir, gate, strings.TrimSpace(string(bootID)), true); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Client) initPersistent(dir string, gate *operation.Gate, boot string, start bool) error {
	store, tasks, err := openStore(dir)
	if err != nil {
		return err
	}
	if gate == nil {
		gate = operation.New()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &tracker{store: store, tasks: tasks, gate: gate, bootID: boot, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), lastProgress: time.Now()}
	p.bootConfirmed, p.runningVersion = openRCConfirmed, currentVersion
	p.processScan = updaterPresent
	c.persistent = p
	if err := c.restorePending(); err != nil {
		cancel()
		return err
	}
	// Reserve before serving any HTTP requests, including the updater's download
	// phase. Later observation proves completion or resolves uncertainty.
	if p.external != nil {
		lease, err := gate.TryAcquire("update-recovery")
		if err != nil {
			cancel()
			return err
		}
		p.lease, p.active = lease, p.external.ID
	} else {
		for i := len(p.tasks) - 1; i >= 0; i-- {
			t := p.tasks[i]
			if t.State == Submitted || t.State == Installing || t.State == RunningExternal || t.State == Unknown && !resolvedBootOutcome(t) || externalMayRun(t, boot, p.processScan) {
				lease, e := gate.TryAcquire("update-recovery")
				if e != nil {
					return e
				}
				p.lease, p.active = lease, t.ID
			}
			break
		}
	}
	if start {
		go c.observe(ctx)
	} else {
		close(p.done)
	}
	return nil
}
func (c *Client) observe(ctx context.Context) {
	p := c.persistent
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.wake:
		}
		c.mu.Lock()
		needed := p.active != ""
		if !needed {
			for _, t := range p.tasks {
				if t.State == InstalledPendingReboot && t.BootID != p.bootID {
					needed = true
					break
				}
			}
		}
		if needed && !c.closed {
			bounded, cancel := context.WithTimeout(ctx, callTimeout)
			status, err := c.status(bounded)
			if err == nil {
				err = c.reconcile(bounded, status)
			}
			cancel()
			if err != nil && !errors.Is(err, ErrPersistence) {
				if p.unavailableSince.IsZero() {
					p.unavailableSince = time.Now()
				}
				if p.active != "" && time.Since(p.unavailableSince) > 30*time.Second {
					c.observationUnavailable()
				}

			} else if err == nil {
				p.unavailableSince = time.Time{}
			}
		}
		c.mu.Unlock()
	}
}
func (c *Client) notify() {
	select {
	case c.persistent.wake <- struct{}{}:
	default:
	}
}
func (c *Client) findTask(id string) (Task, bool) {
	if c.persistent.external != nil && c.persistent.external.ID == id {
		return *c.persistent.external, true
	}
	for _, t := range c.persistent.tasks {
		if t.ID == id {
			return t, true
		}
	}
	return Task{}, false
}
func (c *Client) prior(requestID, path, source string) (Task, bool, error) {
	if requestID == "" {
		return Task{}, false, nil
	}
	records := c.persistent.tasks
	if c.persistent.external != nil {
		records = append(append([]Task(nil), records...), *c.persistent.external)
	}
	if c.persistent.lastEmpty != nil {
		records = append(append([]Task(nil), records...), *c.persistent.lastEmpty)
	}
	for _, t := range records {
		if t.RequestID == requestID {
			if t.Path != path || t.Source != source {
				return Task{}, true, ErrConflict
			}
			return cloneTask(t), true, c.persistent.saveError
		}
	}
	return Task{}, false, nil
}
func (c *Client) commit(t Task) error {
	p := c.persistent
	if p.external != nil && p.external.ID == t.ID {
		return c.persistExternal(t)
	}
	found := false
	for _, old := range p.tasks {
		if old.ID == t.ID {
			found = true
			break
		}
	}
	if !found && t.Source == "hawkbit" && t.State == RunningExternal {
		return c.persistExternal(t)
	}
	return c.commitHistory(t)
}

func (c *Client) commitHistory(t Task) error {
	p := c.persistent
	index := -1
	for i, old := range p.tasks {
		if old.ID == t.ID {
			if sameTask(old, t) {
				return nil
			}
			index = i
			t.UpdatedAt = time.Now().UTC()
			break
		}
	}
	// An unchanged observation must not allocate a replacement history.
	next := make([]Task, len(p.tasks))
	copy(next, p.tasks)
	if index >= 0 {
		next[index] = cloneTask(t)
	} else {
		next = append(next, cloneTask(t))
	}
	if len(next) > maxTasks {
		next = next[len(next)-maxTasks:]
	}
	if err := p.store.save(next); err != nil {
		p.saveError = fmt.Errorf("%w: %v", ErrPersistence, err)
		return p.saveError
	}
	p.tasks = next
	p.saveError = nil
	return nil
}
func (c *Client) acquire(kind string) error {
	p := c.persistent
	if p.active != "" {
		return ErrBusy
	}
	lease, err := p.gate.TryAcquire(kind)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBusy, err)
	}
	p.lease = lease
	return nil
}
func (c *Client) releaseTask() {
	p := c.persistent
	p.lease.Release()
	p.lease = nil
	p.active = ""
	c.pending = false
}
func (c *Client) Tasks() ([]Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistent == nil {
		return []Task{}, nil
	}
	out := make([]Task, 0, len(c.persistent.tasks)+1)
	if external := c.persistent.external; external != nil {
		inHistory := false
		for _, record := range c.persistent.tasks {
			if record.ID == external.ID {
				inHistory = true
				break
			}
		}
		if !inHistory {
			out = append(out, cloneTask(*external))
		}
	}
	for i := len(c.persistent.tasks) - 1; i >= 0; i-- {
		out = append(out, cloneTask(c.persistent.tasks[i]))
	}
	return out, c.persistent.saveError
}
func (c *Client) Task(id string) (Task, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistent != nil {
		if t, ok := c.findTask(id); ok {
			return cloneTask(t), c.persistent.saveError
		}
	}
	return Task{}, ErrNotFound
}

func validateRequest(path, id string) (string, error) {
	if !filepath.IsAbs(path) || len(path) > 4096 || strings.ContainsRune(path, 0) || id != "" && !validID(id) {
		return "", ErrInvalid
	}
	return filepath.Clean(path), nil
}
func (c *Client) prepare(ctx context.Context, source, path, id, version, action string) (Task, error) {
	status, err := c.status(ctx)
	if err != nil {
		return Task{}, err
	}
	if status.Operation != "idle" || status.Pending {
		return Task{}, ErrBusy
	}
	snapshot, err := c.snapshot(ctx)
	if err != nil {
		return Task{}, err
	}
	slot, err := target(snapshot)
	if err != nil {
		return Task{}, err
	}
	taskID, err := taskID()
	if err != nil {
		return Task{}, err
	}
	now := time.Now().UTC()
	return Task{ID: taskID, RequestID: id, Source: source, Path: path, ActionID: action, State: Submitted, CreatedAt: now, UpdatedAt: now, Version: version, BootID: c.persistent.bootID, TargetSlot: slot.Name, TargetBootname: slot.Bootname, BootSlot: snapshot.BootSlot, Primary: snapshot.Primary, Before: snapshot.Slots}, nil
}

func (c *Client) InstallRequest(ctx context.Context, path, requestID string) (Task, error) {
	if c.persistent == nil {
		return Task{}, errors.New("persistent update tracking is not configured")
	}
	path, err := validateRequest(path, requestID)
	if err != nil {
		return Task{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, found, err := c.prior(requestID, path, "local"); found {
		return t, err
	}
	if err = c.acquire("local-update"); err != nil {
		return Task{}, err
	}
	keep := false
	defer func() {
		if !keep {
			c.releaseTask()
		}
	}()
	info, err := os.Lstat(path)
	if err != nil {
		return Task{}, err
	}
	if !info.Mode().IsRegular() {
		return Task{}, ErrInvalid
	}
	t, err := c.prepare(ctx, "local", path, requestID, "", "")
	if err != nil {
		return Task{}, err
	}
	bundle, err := c.inspectBundle(ctx, path)
	if err != nil {
		return Task{}, err
	}
	t.Version, t.ManifestHash, t.Images = bundle.Version, bundle.Hash, bundle.Images
	if loaderImages(t.Images) {
		original, ok := actualRoot(t.Before, t.BootSlot)
		if !ok || original.BootStatus != "good" || t.Primary != original.Name || !checkTopology(t.Before) {
			return Task{}, errors.New("bootloader update requires a confirmed running primary OS slot")
		}
		if _, _, ok := loaderPair(t.Before); !ok {
			return Task{}, errors.New("bootloader update requires the shared uboot and idb slots")
		}
		t.TargetSlot, t.TargetBootname = original.Name, original.Bootname
	}
	// Queue durably before making a call whose remote acceptance could outlive
	// a connection or the Core process. No successful commit => no Install call.
	if err = c.commit(t); err != nil {
		return Task{}, err
	}
	p := c.persistent
	p.active = t.ID
	p.lastProgress = time.Now()
	keep = true
	c.pending, c.path, c.result = true, path, nil
	c.completionAfter = c.observed
	options := map[string]dbus.Variant{"transaction-id": dbus.MakeVariant(t.ID), "require-manifest-hash": dbus.MakeVariant(t.ManifestHash)}
	call := c.object.CallWithContext(ctx, installer+".InstallBundle", dbus.FlagNoAutoStart, path, options)
	if call.Err != nil {
		t.Error = "RAUC acceptance is uncertain: " + call.Err.Error()
		var remote dbus.Error
		var remotePtr *dbus.Error
		if errors.As(call.Err, &remotePtr) {
			remote = *remotePtr
		} else {
			_ = errors.As(call.Err, &remote)
		}
		if remote.Name != "" && !ownerGone(call.Err) {
			t.State = Failed
			t.Error = call.Err.Error()
			if err = c.commit(t); err != nil {
				return cloneTask(t), err
			}
			c.releaseTask()
			if len(remote.Body) == 1 && remote.Body[0] == "Already processing a different method" {
				return cloneTask(t), ErrBusy
			}
			return cloneTask(t), call.Err
		}
		if err = c.commit(t); err != nil {
			return cloneTask(t), err
		}
		c.notify()
		return cloneTask(t), call.Err
	}
	t.State = Installing
	if err = c.commit(t); err != nil {
		return cloneTask(t), err
	}
	c.notify()
	return cloneTask(t), nil
}

func (c *Client) BeginExternal(ctx context.Context, request ExternalRequest) (Task, error) {
	if c.persistent == nil {
		return Task{}, errors.New("persistent update tracking is not configured")
	}
	if request.Source == "" {
		request.Source = "hawkbit"
	}
	if request.Source != "hawkbit" || request.RequestID == "" || len(request.Version) > 256 || len(request.ActionID) > 128 {
		return Task{}, ErrInvalid
	}
	path, err := validateRequest(request.Path, request.RequestID)
	if err != nil {
		return Task{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, found, err := c.prior(request.RequestID, path, request.Source); found {
		if err != nil {
			return t, err
		}
		if t.State == InstalledPendingReboot || t.State == BootConfirmed || t.State == Failed || resolvedBootOutcome(t) || emptyCheck(t) {
			return t, nil
		}
		p := c.persistent
		if p.active != "" && p.active != t.ID {
			return Task{}, ErrBusy
		}
		if p.lease == nil {
			if err := c.acquire("hawkbit-update"); err != nil {
				return Task{}, err
			}
		}
		t.State = RunningExternal
		if err := c.commit(t); err != nil {
			if p.active == "" {
				c.releaseTask()
			}
			return t, err
		}
		p.active = t.ID
		p.lastProgress = time.Now()
		c.pending = true
		c.notify()
		return t, nil
	}
	if err := c.acquire("hawkbit-update"); err != nil {
		return Task{}, err
	}
	keep := false
	defer func() {
		if !keep {
			c.releaseTask()
		}
	}()
	t, err := c.prepare(ctx, request.Source, path, request.RequestID, request.Version, request.ActionID)
	if err != nil {
		return Task{}, err
	}
	t.State = RunningExternal
	p := c.persistent
	p.active = t.ID
	p.lastProgress = time.Now()
	c.pending, c.path, c.result = true, path, nil
	c.completionAfter = c.observed
	keep = true
	if err := c.commit(t); err != nil {
		c.notify()
		return Task{}, err
	}
	c.notify()
	return cloneTask(t), nil
}
func (c *Client) AttachExternal(ctx context.Context, id string, identity ExternalIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistent == nil {
		return ErrNotFound
	}
	t, ok := c.findTask(id)
	if !ok || t.Source != "hawkbit" {
		return ErrNotFound
	}
	if !processAlive(&identity, c.persistent.bootID) || c.persistent.active != id || identity.PID <= 0 || identity.StartTime == 0 || identity.BootID != c.persistent.bootID || !filepath.IsAbs(identity.Exe) || !filepath.IsAbs(identity.ConfigPath) || len(identity.ConfigSHA256) != 64 {
		return ErrInvalid
	}
	info, err := os.Lstat(identity.ConfigPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return ErrInvalid
	}
	config, err := os.ReadFile(identity.ConfigPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(config)
	if !strings.EqualFold(identity.ConfigSHA256, hex.EncodeToString(sum[:])) {
		return ErrInvalid
	}
	identity.ConfigSHA256 = strings.ToLower(identity.ConfigSHA256)
	t.ExternalIdentity = &identity
	return c.commit(t)
}
func (c *Client) EndExternal(ctx context.Context, id string, exitCode int, runErr error) (Task, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistent == nil {
		return Task{}, ErrNotFound
	}
	if recent := c.persistent.lastEmpty; recent != nil && recent.ID == id {
		return cloneTask(*recent), nil
	}
	t, ok := c.findTask(id)
	if !ok || t.Source != "hawkbit" {
		return Task{}, ErrNotFound
	}
	if t.State == BootConfirmed || t.State == InstalledPendingReboot || t.State == Failed || resolvedBootOutcome(t) || emptyCheck(t) {
		t.UpdaterExit = &exitCode
		if err := c.commit(t); err != nil {
			return t, err
		}
		if c.persistent.active == id {
			c.releaseTask()
		}
		return cloneTask(t), nil
	}
	t.UpdaterExit = &exitCode
	if runErr != nil {
		t.Error = "updater process failed"
	}
	if err := c.commit(t); err != nil {
		return t, err
	}
	status, err := c.status(ctx)
	if err == nil {
		err = c.reconcile(ctx, status)
	}
	if errors.Is(err, ErrPersistence) {
		return cloneTask(t), err
	}
	if err != nil {
		t.State, t.Error = Unknown, "updater exited; RAUC evidence unavailable"
		if saveErr := c.commit(t); saveErr != nil {
			return t, saveErr
		}
		c.releaseTask()
		return cloneTask(t), err
	}
	if recent := c.persistent.lastEmpty; recent != nil && recent.ID == id {
		return cloneTask(*recent), nil
	}
	latest, _ := c.findTask(id)
	return cloneTask(latest), nil
}

func (c *Client) observationUnavailable() {
	p := c.persistent
	if p.saveError != nil {
		return
	}
	t, ok := c.findTask(p.active)
	if !ok {
		return
	}
	alive := externalMayRun(t, p.bootID, p.processScan)
	t.State, t.Error = Unknown, "RAUC observation unavailable; installation result is unknown"
	if c.commit(t) == nil && !alive {
		c.releaseTask()
	}
}
