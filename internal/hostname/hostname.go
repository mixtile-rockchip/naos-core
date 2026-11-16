// Package hostname applies a valid OEM serial number as the Linux hostname.
package hostname

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"naos.local/core/internal/oem"
)

// Apply returns a nonempty name only after the kernel hostname is confirmed.
// A subsequent persistence error does not invalidate that applied name.
func Apply(soc string) (string, error) {
	info, err := oem.Read(soc)
	if err != nil {
		return "", err
	}
	return apply(info.SN, "/etc/hostname", os.Hostname, syscall.Sethostname)
}

func serialName(sn [16]byte) (string, error) {
	for i, b := range sn {
		alnum := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		if !alnum && !(b == '-' && i > 0 && i < len(sn)-1) {
			return "", errors.New("OTP SN is not a valid hostname")
		}
	}
	name := string(sn[:])
	if name == "0000000000000000" {
		return "", errors.New("OTP SN is all zero")
	}
	return name, nil
}

func apply(sn [16]byte, path string, current func() (string, error), set func([]byte) error) (string, error) {
	name, err := serialName(sn)
	if err != nil {
		return "", err
	}
	old, err := current()
	if err != nil {
		return "", fmt.Errorf("read Linux hostname: %w", err)
	}
	if old != name {
		if err := set([]byte(name)); err != nil {
			return "", fmt.Errorf("set Linux hostname: %w", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return name, fmt.Errorf("read hostname file: %w", err)
	}
	if strings.TrimSpace(string(data)) != name {
		if err := os.WriteFile(path, []byte(name+"\n"), 0644); err != nil {
			return name, fmt.Errorf("persist hostname: %w", err)
		}
	}
	return name, nil
}
