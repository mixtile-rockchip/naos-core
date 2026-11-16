// Package recovery queues the initramfs's versioned whole-userdata reset.
package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	Offset    = 65536
	Size      = 512
	miscBytes = 4 * 1024 * 1024
)

// ErrUncertain means a request write may be durable despite an I/O failure.
// Callers must keep the update/reboot guard and report failure.
var ErrUncertain = errors.New("recovery state requires inspection")

// Record is ASCII padded to 256 bytes, its lowercase SHA256, then 192 zeroes.
func record() []byte {
	data := make([]byte, Size)
	for i := 0; i < 256; i++ {
		data[i] = ' '
	}
	copy(data[:256], "NAOS-RECOVERY\nversion=3\noperation=clear-userdata")
	sum := sha256.Sum256(data[:256])
	hex.Encode(data[256:320], sum[:])
	return data
}

// arm writes only the assigned sector and never overwrites an unknown request.
func arm(f *os.File, wanted []byte) error {
	current := make([]byte, Size)
	if _, err := f.ReadAt(current, Offset); err != nil {
		return fmt.Errorf("read recovery record: %w", err)
	}
	if !bytes.Equal(current, make([]byte, Size)) && !bytes.Equal(current, wanted) {
		return errors.New("misc contains an unknown or damaged recovery record")
	}
	if !bytes.Equal(current, wanted) {
		n, err := f.WriteAt(wanted, Offset)
		if err != nil {
			return fmt.Errorf("%w: write recovery record: %v", ErrUncertain, err)
		}
		if n != len(wanted) {
			return fmt.Errorf("%w: %v", ErrUncertain, io.ErrShortWrite)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("%w: sync recovery record: %v", ErrUncertain, err)
	}
	if _, err := f.ReadAt(current, Offset); err != nil {
		return fmt.Errorf("%w: verify recovery record: %v", ErrUncertain, err)
	}
	if !bytes.Equal(current, wanted) {
		return fmt.Errorf("%w: recovery record readback differs", ErrUncertain)
	}
	return nil
}

// Request durably queues recovery. The caller may acknowledge and reboot only
// after nil; initramfs clears the request after successfully clearing the existing filesystem.
func Request(ctx context.Context) error {
	device, err := filepath.EvalSymlinks("/dev/naos/misc")
	if err != nil {
		return err
	}
	fd, err := syscall.Open(device, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), device)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat("/dev/naos/misc")
	if err != nil || !os.SameFile(info, current) || info.Mode()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice {
		return errors.New("misc device changed during validation")
	}
	var capacity uint64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x80081272, uintptr(unsafe.Pointer(&capacity))) // BLKGETSIZE64
	if errno != 0 || capacity != miscBytes {
		return errors.New("opened misc capacity does not match layout")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return arm(f, record())
}
