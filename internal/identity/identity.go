// Package identity resolves and persists the hawkBit controller ID in device.ini.
package identity

import (
	"crypto/rand"
	"fmt"
	"io"

	"naos.local/core/internal/config"
	"naos.local/core/internal/oem"
)

// Resolve preserves a configured ID. An empty ID becomes SN-- plus a valid
// 16-byte serial, or NN plus 18 random alphanumeric characters. The first ID
// is atomically saved to this same INI and reused, even if OTP later changes.
// knownSN reuses the serve path's read; check may leave it empty to read OTP.
func Resolve(soc, configPath, knownSN string) (string, error) {
	return resolve(soc, configPath, knownSN, oem.Read, rand.Reader)
}

func resolve(soc, path, knownSN string, readOEM func(string) (oem.Info, error), random io.Reader) (string, error) {
	return config.EnsureControllerID(path, func() (string, error) {
		id, err := generate(soc, knownSN, readOEM, random)
		if err != nil {
			return "", fmt.Errorf("generate controller identity: %w", err)
		}
		return id, nil
	})
}

func validSN(sn string) bool {
	if len(sn) != 16 || sn == "0000000000000000" {
		return false
	}
	for i := range sn {
		c := sn[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func randomID(random io.Reader) (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	id := []byte("NN000000000000000000")
	var bytes [32]byte
	for n := 2; n < len(id); {
		if _, err := io.ReadFull(random, bytes[:]); err != nil {
			return "", err
		}
		for _, value := range bytes {
			if value >= 248 {
				continue
			} // Four equal-sized sets of 62 values.
			id[n] = alphabet[int(value)%len(alphabet)]
			n++
			if n == len(id) {
				break
			}
		}
	}
	return string(id), nil
}
