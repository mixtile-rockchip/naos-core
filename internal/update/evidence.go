package update

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

type slotTuple struct {
	Name   string
	Values map[string]dbus.Variant
}
type snapshot struct {
	BootSlot, Primary string
	Slots             []SlotEvidence
}
type bundleInfo struct {
	Version, Hash string
	Images        map[string]string
}

func text(v map[string]dbus.Variant, key string) string {
	value, _ := unwrap(v[key].Value()).(string)
	return value
}
func unwrap(v any) any {
	for {
		w, ok := v.(dbus.Variant)
		if !ok {
			return v
		}
		v = w.Value()
	}
}
func dictionary(v any) map[string]dbus.Variant { m, _ := unwrap(v).(map[string]dbus.Variant); return m }

// Only read-only RAUC methods are used for recovery. Core never Mark()s a slot.
func (c *Client) snapshot(ctx context.Context) (snapshot, error) {
	var slots []slotTuple
	if err := c.object.CallWithContext(ctx, installer+".GetSlotStatus", dbus.FlagNoAutoStart).Store(&slots); err != nil {
		return snapshot{}, fmt.Errorf("RAUC slot status: %w", err)
	}
	if len(slots) < 2 || len(slots) > 32 {
		return snapshot{}, errors.New("invalid RAUC slot count")
	}
	s := snapshot{BootSlot: c.bootSlot}
	if s.BootSlot == "" {
		return s, errors.New("RAUC BootSlot is unavailable")
	}
	if err := c.object.CallWithContext(ctx, installer+".GetPrimary", dbus.FlagNoAutoStart).Store(&s.Primary); err != nil {
		return s, fmt.Errorf("RAUC primary: %w", err)
	}
	seen := map[string]bool{}
	for _, row := range slots {
		if row.Name == "" || seen[row.Name] {
			return s, errors.New("invalid RAUC slot identity")
		}
		seen[row.Name] = true
		v := row.Values
		count, _ := v["installed.count"].Value().(uint32)
		s.Slots = append(s.Slots, SlotEvidence{Name: row.Name, Class: text(v, "class"), Parent: text(v, "parent"), Device: text(v, "device"), Bootname: text(v, "bootname"), State: text(v, "state"), BootStatus: text(v, "boot-status"), Version: text(v, "bundle.version"), ManifestHash: text(v, "bundle.hash"), SHA256: text(v, "sha256"), Status: text(v, "status"), Transaction: text(v, "installed.transaction"), InstalledAt: text(v, "installed.timestamp"), InstalledCount: count})
	}
	return s, nil
}
func booted(s SlotEvidence, boot string) bool {
	return s.State == "booted" || s.Name == boot || s.Bootname == boot || s.Device == boot
}
func target(s snapshot) (SlotEvidence, error) {
	var found []SlotEvidence
	for _, slot := range s.Slots {
		if slot.Class == "rootfs" && slot.Parent == "" && !booted(slot, s.BootSlot) {
			found = append(found, slot)
		}
	}
	if len(found) != 1 || found[0].Bootname == "" {
		return SlotEvidence{}, errors.New("cannot unambiguously select inactive rootfs slot")
	}
	return found[0], nil
}
func (c *Client) inspectBundle(ctx context.Context, path string) (bundleInfo, error) {
	var info map[string]dbus.Variant
	if err := c.object.CallWithContext(ctx, installer+".InspectBundle", dbus.FlagNoAutoStart, path, map[string]dbus.Variant{}).Store(&info); err != nil {
		return bundleInfo{}, fmt.Errorf("RAUC verify bundle: %w", err)
	}
	result := bundleInfo{Hash: text(info, "manifest-hash"), Images: map[string]string{}}
	result.Version = text(dictionary(info["update"].Value()), "version")
	images, ok := unwrap(info["images"].Value()).([]map[string]dbus.Variant)
	if !ok {
		return result, errors.New("invalid RAUC manifest images")
	}
	for _, image := range images {
		class, digest := text(image, "slot-class"), text(image, "checksum")
		if class == "" || !checksum(digest) || result.Images[class] != "" {
			return result, errors.New("ambiguous RAUC manifest images")
		}
		result.Images[class] = strings.ToLower(digest)
	}
	if !checksum(result.Hash) || !systemImages(result.Images) && !loaderImages(result.Images) {
		return result, errors.New("bundle requires a signed manifest with exactly rootfs and boot, or uboot and idb checksums")
	}
	return result, nil
}
