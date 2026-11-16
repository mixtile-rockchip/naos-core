//go:build linux && (amd64 || arm64 || arm)

// Package watchdog wraps the Linux watchdog UAPI. The low-level Device never
// feeds by itself; Manager feeds only after the application's health check.
package watchdog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Linux asm-generic UAPI constants, with a 32-bit C int on all supported targets.
const (
	getSupport       = uintptr(0x80285700)
	setOptions       = uintptr(0x80045704)
	keepalive        = uintptr(0x80045705)
	setTimeout       = uintptr(0xc0045706)
	getTimeout       = uintptr(0x80045707)
	DisableCard      = int32(1)
	OptionSetTimeout = uint32(0x0080)
	OptionMagicClose = uint32(0x0100)
	OptionKeepalive  = uint32(0x8000)
)

var ErrClosed = errors.New("watchdog descriptor is closed")

// OpenStateError reports an error after open may already have armed hardware.
// The fd is no longer owned, but its close is not a stop confirmation.
type OpenStateError struct{ Err error }

func (e *OpenStateError) Error() string {
	return "post-open device identity changed; fd closed but watchdog may remain active: " + e.Err.Error()
}
func (e *OpenStateError) Unwrap() error { return e.Err }

type wireInfo struct {
	Options  uint32
	Firmware uint32
	Identity [32]byte
}

type Support struct {
	Options       uint32 `json:"options"`
	Firmware      uint32 `json:"firmware"`
	Identity      string `json:"identity"`
	CanSetTimeout bool   `json:"can_set_timeout"`
	HasMagicClose bool   `json:"has_magic_close"`
	CanKeepalive  bool   `json:"can_keepalive"`
}

type rawHandle interface {
	ioctl(uintptr, unsafe.Pointer) error
	write([]byte) (int, error)
	stat() (syscall.Stat_t, error)
	close() error
}

type opener interface {
	lstat(string) (syscall.Stat_t, error)
	open(string, int) (rawHandle, error)
}

type system struct{}
type descriptor int

func (system) lstat(path string) (s syscall.Stat_t, err error) { err = syscall.Lstat(path, &s); return }
func (system) open(path string, flags int) (rawHandle, error) {
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	return descriptor(fd), nil
}
func (d descriptor) ioctl(request uintptr, argument unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(d), request, uintptr(argument))
	runtime.KeepAlive(argument)
	if errno != 0 {
		return errno
	}
	return nil
}
func (d descriptor) write(data []byte) (int, error)      { return syscall.Write(int(d), data) }
func (d descriptor) stat() (s syscall.Stat_t, err error) { err = syscall.Fstat(int(d), &s); return }
func (d descriptor) close() error                        { return syscall.Close(int(d)) }

// Device has no finalizer: its owner must explicitly choose whether to stop
// the user watchdog or close while leaving it running.
type Device struct {
	mu     sync.Mutex
	raw    rawHandle
	closed bool
}

// Open opens a pre-inspected, explicit character node. Opening itself may start
// the watchdog. No GETSUPPORT/SETTIMEOUT/enable call or background feeder is
// hidden in Open. The caller must retain the returned handle until cleanup.
// A post-open identity race closes the fd and returns an error explicitly
// stating that the watchdog's state may be active; no stop is claimed.
func Open(path string, expectedDevice uint64) (*Device, error) {
	return openWith(system{}, path, expectedDevice)
}

func openWith(ops opener, path string, expectedDevice uint64) (*Device, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || expectedDevice == 0 {
		return nil, errors.New("expected an absolute device path and inspected device number")
	}
	before, err := ops.lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat watchdog: %w", err)
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFCHR || uint64(before.Rdev) != expectedDevice {
		return nil, errors.New("watchdog path is not the inspected character device (symlinks refused)")
	}
	raw, err := ops.open(path, syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW)
	if err != nil {
		return nil, fmt.Errorf("open watchdog: %w", err)
	}
	after, statErr := raw.stat()
	if statErr != nil || after.Mode&syscall.S_IFMT != syscall.S_IFCHR || uint64(after.Rdev) != expectedDevice || after.Dev != before.Dev || after.Ino != before.Ino {
		closeErr := raw.close()
		return nil, &OpenStateError{Err: errors.Join(statErr, closeErr, errors.New("identity mismatch"))}
	}
	return &Device{raw: raw}, nil
}

func (d *Device) Support() (Support, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return Support{}, ErrClosed
	}
	var w wireInfo
	if err := d.raw.ioctl(getSupport, unsafe.Pointer(&w)); err != nil {
		return Support{}, err
	}
	identity := w.Identity[:]
	if i := bytes.IndexByte(identity, 0); i >= 0 {
		identity = identity[:i]
	}
	return Support{w.Options, w.Firmware, strings.ToValidUTF8(string(identity), "?"), w.Options&OptionSetTimeout != 0, w.Options&OptionMagicClose != 0, w.Options&OptionKeepalive != 0}, nil
}

func (d *Device) timeoutLocked() (int32, error) {
	var seconds int32
	if err := d.raw.ioctl(getTimeout, unsafe.Pointer(&seconds)); err != nil {
		return 0, err
	}
	if seconds <= 0 {
		return 0, errors.New("driver returned a non-positive timeout")
	}
	return seconds, nil
}
func (d *Device) Timeout() (int32, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, ErrClosed
	}
	return d.timeoutLocked()
}

// SetTimeout reads the effective value back using GETTIMEOUT. The kernel can
// quantize the requested timeout. It may have changed even if readback fails.
func (d *Device) SetTimeout(seconds int32) (int32, error) {
	if seconds <= 0 {
		return 0, errors.New("timeout must be positive C-int seconds")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, ErrClosed
	}
	value := seconds
	if err := d.raw.ioctl(setTimeout, unsafe.Pointer(&value)); err != nil {
		return 0, err
	}
	return d.timeoutLocked()
}
func (d *Device) KeepAlive() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	var ignored int32
	return d.raw.ioctl(keepalive, unsafe.Pointer(&ignored))
}

type CloseResult struct {
	UserWatchdogDisabled     bool `json:"user_watchdog_disabled"`
	FDClosed                 bool `json:"fd_closed"`
	MagicCloseWritten        bool `json:"magic_close_written"`
	HardwareStoppedConfirmed bool `json:"hardware_stopped_confirmed"`
}

// StopUserAndClose uses DISABLECARD, then closes the descriptor. A successful
// ioctl only proves the kernel accepted disabling userspace ownership. A
// driver without a reset/stop operation may leave hardware running and have
// the kernel feed it. HardwareStoppedConfirmed therefore remains false.
// If DISABLECARD fails, the descriptor remains held for KeepAlive/retry.
func (d *Device) StopUserAndClose() (CloseResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return CloseResult{FDClosed: true}, ErrClosed
	}
	value := DisableCard
	if err := d.raw.ioctl(setOptions, unsafe.Pointer(&value)); err != nil {
		return CloseResult{}, err
	}
	r := CloseResult{UserWatchdogDisabled: true}
	d.closed = true // Linux close must never be retried against a reused fd.
	err := d.raw.close()
	r.FDClosed = true
	return r, err
}

// MagicClose is deliberately explicit. Writing V and a successful close do
// not confirm that a driver stopped, especially with nowayout or absent reset.
// The caller must have established this policy before opening the watchdog.
func (d *Device) MagicClose() (CloseResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return CloseResult{FDClosed: true}, ErrClosed
	}
	n, err := d.raw.write([]byte{'V'})
	if err != nil {
		return CloseResult{}, err
	}
	if n != 1 {
		return CloseResult{}, errors.New("short magic-close write; descriptor remains held")
	}
	d.closed = true
	r := CloseResult{FDClosed: true, MagicCloseWritten: true}
	return r, d.raw.close()
}

// CloseWithoutStopping is an emergency ownership operation, never automatic.
// Hardware or the user watchdog may remain active after it returns.
func (d *Device) CloseWithoutStopping() (CloseResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return CloseResult{FDClosed: true}, ErrClosed
	}
	d.closed = true
	return CloseResult{FDClosed: true}, d.raw.close()
}

// ValidateCharacterNode is read-only and never opens the device.
func ValidateCharacterNode(path string) (uint64, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return 0, errors.New("expected an absolute device path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeCharDevice == 0 {
		return 0, errors.New("expected an explicit character node, not a symlink")
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("character-node stat unavailable")
	}
	return uint64(s.Rdev), nil
}
