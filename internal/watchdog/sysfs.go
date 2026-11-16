package watchdog

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Inspection struct {
	Device                string `json:"device"`
	DeviceNumber          uint64 `json:"device_number"`
	SysfsDevice           string `json:"sysfs_device"`
	Identity              string `json:"identity"`
	Driver                string `json:"driver"`
	State                 string `json:"state"`
	Nowayout              *bool  `json:"nowayout"`
	TimeoutSeconds        int32  `json:"timeout_seconds"`
	ResetPropertyPresent  bool   `json:"reset_property_present"`
	HardwareStopSupported *bool  `json:"hardware_stop_supported"`
	HardwareStopReason    string `json:"hardware_stop_reason"`
}

func readText(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", errors.New("sysfs attribute exceeds 4096 bytes")
	}
	return strings.TrimSpace(string(b)), nil
}

// Inspect uses sysfs and lstat only, never open(2) on /dev/watchdogN. Explicit
// numbered nodes avoid the ambiguous legacy /dev/watchdog alias.
func Inspect(device string) (Inspection, error) {
	return inspectWith(device, "/sys/class/watchdog", ValidateCharacterNode)
}

func inspectWith(device, root string, validate func(string) (uint64, error)) (Inspection, error) {
	r := Inspection{Device: device, HardwareStopReason: "driver stop/reset path has not been established"}
	base := filepath.Base(device)
	if !regexp.MustCompile(`^watchdog[0-9]+$`).MatchString(base) {
		return r, errors.New("use an explicit numbered watchdog character node")
	}
	number, err := validate(device)
	if err != nil {
		return r, err
	}
	r.DeviceNumber = number
	entry := filepath.Join(root, base)
	if r.SysfsDevice, err = readText(filepath.Join(entry, "dev")); err != nil {
		return r, err
	}
	major := (number>>8)&0xfff | (number>>32)&^uint64(0xfff)
	minor := number&0xff | (number>>12)&^uint64(0xff)
	if r.SysfsDevice != fmt.Sprintf("%d:%d", major, minor) {
		return r, errors.New("device number does not match sysfs watchdog node")
	}
	if r.Identity, err = readText(filepath.Join(entry, "identity")); err != nil {
		return r, err
	}
	if r.State, err = readText(filepath.Join(entry, "state")); err != nil {
		return r, err
	}
	value, err := readText(filepath.Join(entry, "nowayout"))
	if err != nil {
		return r, err
	}
	switch value {
	case "0":
		v := false
		r.Nowayout = &v
	case "1":
		v := true
		r.Nowayout = &v
	default:
		return r, errors.New("unknown nowayout value")
	}
	value, err = readText(filepath.Join(entry, "timeout"))
	if err != nil {
		return r, err
	}
	timeout, err := strconv.ParseInt(value, 10, 32)
	if err != nil || timeout <= 0 {
		return r, errors.New("invalid sysfs timeout")
	}
	r.TimeoutSeconds = int32(timeout)
	driver, err := os.Readlink(filepath.Join(entry, "device", "driver"))
	if err == nil {
		r.Driver = filepath.Base(driver)
	}
	reset, err := os.Stat(filepath.Join(entry, "device", "of_node", "resets"))
	if err == nil {
		r.ResetPropertyPresent = reset.Size() > 0
	} else if !os.IsNotExist(err) {
		return r, err
	}
	if r.Driver == "dw_wdt" {
		available := r.ResetPropertyPresent
		r.HardwareStopSupported = &available
		if available {
			r.HardwareStopReason = "DesignWare reset property exists; verify platform reset wiring before exercising"
		} else {
			r.HardwareStopReason = "DesignWare without reset: disabling userspace can leave hardware running under kernel feeding"
		}
	}
	return r, nil
}

// ValidateExercise is intentionally conservative. It does not open a device.
func ValidateExercise(r Inspection) error {
	if r.State != "inactive" {
		return errors.New("refusing to take over a non-inactive watchdog")
	}
	if r.Nowayout == nil || *r.Nowayout {
		return errors.New("short exercise requires confirmed nowayout=false")
	}
	if r.HardwareStopSupported == nil || !*r.HardwareStopSupported {
		return errors.New("short exercise refused: no established hardware stop/reset path")
	}
	return nil
}

// OpenForExercise is a conservative test gate, not the product's takeover
// policy. The general Open primitive remains available for an explicitly
// chosen long-lived platform owner even when hardware cannot be stopped.
func OpenForExercise(r Inspection) (*Device, error) { return openExerciseWith(system{}, r) }
func openExerciseWith(ops opener, r Inspection) (*Device, error) {
	if err := ValidateExercise(r); err != nil {
		return nil, err
	}
	return openWith(ops, r.Device, r.DeviceNumber)
}
