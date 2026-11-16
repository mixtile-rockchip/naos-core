package update

import (
	"context"
	"errors"

	"naos.local/core/internal/operation"
)

// PrepareAutoReboot authorizes the latest completed installation only. The
// caller owns the returned lease and invokes reboot outside the update lock.
// attemptedID prevents repeated attempts for one task within that process.
func (c *Client) PrepareAutoReboot(ctx context.Context, attemptedID string) (Task, *operation.Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.persistent
	if p == nil || len(p.tasks) == 0 {
		return Task{}, nil, nil
	}
	t := p.tasks[len(p.tasks)-1]
	if t.ID == attemptedID {
		return Task{}, nil, nil
	}
	if p.saveError != nil {
		return Task{}, nil, p.saveError
	}
	if p.active != "" || t.State != InstalledPendingReboot || t.BootID != p.bootID || t.Result != nil && *t.Result != 0 || t.Source == "hawkbit" && (t.UpdaterExit == nil || *t.UpdaterExit != 0) || !verifiedRebootTask(t) {
		return Task{}, nil, nil
	}
	if c.closed {
		return Task{}, nil, errors.New("RAUC client is closed")
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Task{}, nil, err
	}
	lease, err := p.gate.TryAcquire("update-auto-reboot")
	if errors.Is(err, operation.ErrBusy) {
		return Task{}, nil, nil
	}
	if err != nil {
		return Task{}, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			lease.Release()
		}
	}()
	status, err := c.status(ctx)
	if err != nil {
		return Task{}, nil, err
	}
	if status.Operation != "idle" || status.Pending {
		return Task{}, nil, nil
	}
	live, err := c.snapshot(ctx)
	if err != nil {
		return Task{}, nil, err
	}
	if bootloaderTask(t) {
		if !unchangedOS(t, live) || !sameInstalledEvidence(t, live) {
			return Task{}, nil, nil
		}
	} else {
		running, bootKnown := actualRoot(live.Slots, live.BootSlot)
		original, originalKnown := actualRoot(t.Before, t.BootSlot)
		target, _, pairKnown := slotPair(live.Slots, t.TargetSlot)
		if !bootKnown || !originalKnown || running.Name != original.Name || running.Name == t.TargetSlot || live.Primary != t.TargetSlot || !pairKnown || target.BootStatus != "good" || !sameInstalledEvidence(t, live) {
			return Task{}, nil, nil
		}
	}
	if p.processScan == nil {
		return Task{}, nil, nil
	}
	present, complete := p.processScan()
	if present || !complete {
		return Task{}, nil, nil
	}
	if err := ctx.Err(); err != nil {
		return Task{}, nil, err
	}
	keep = true
	return cloneTask(t), lease, nil
}

func verifiedRebootTask(t Task) bool {
	if bootloaderTask(t) {
		return verifiedLoaderTask(t)
	}
	root, boot, ok := slotPair(t.Installed, t.TargetSlot)
	if !ok || !completeImage(root) || !completeImage(boot) || root.Bootname == "" || root.Bootname != t.TargetBootname || root.Transaction == "" || root.Transaction != boot.Transaction || root.Version != boot.Version || root.ManifestHash != boot.ManifestHash || t.Version != root.Version || t.ManifestHash != root.ManifestHash {
		return false
	}
	if t.Source != "local" && t.Source != "hawkbit" || t.Source == "local" && root.Transaction != t.ID {
		return false
	}
	return (t.Images["rootfs"] == "" || t.Images["rootfs"] == root.SHA256) && (t.Images["boot"] == "" || t.Images["boot"] == boot.SHA256)
}
