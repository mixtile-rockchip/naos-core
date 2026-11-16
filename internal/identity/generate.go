package identity

import (
	"crypto/rand"
	"io"
	"os"
	"strings"

	"naos.local/core/internal/oem"
)

// Generate uses live hardware, never INI. SN-based IDs are repeatable; hardware
// without a valid SN gets a fresh random ID on each explicit registration.
func Generate() (string, error) {
	soc := detectPlatform(func(path string) ([]byte, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 16*1024+1))
	})
	return generate(soc, "", oem.Read, rand.Reader)
}

func detectPlatform(read func(string) ([]byte, error)) string {
	for _, path := range []string{"/proc/device-tree/compatible", "/sys/firmware/devicetree/base/compatible"} {
		data, err := read(path)
		if err != nil || len(data) > 16*1024 {
			continue
		}
		for _, compatible := range strings.Split(string(data), "\x00") {
			if compatible == "rockchip,rk3588" {
				return "rk3588"
			}
		}
	}
	return ""
}

func generate(soc, knownSN string, readOEM func(string) (oem.Info, error), random io.Reader) (string, error) {
	if validSN(knownSN) {
		return "SN--" + knownSN, nil
	}
	if info, err := readOEM(soc); err == nil && validSN(string(info.SN[:])) {
		return "SN--" + string(info.SN[:]), nil
	}
	return randomID(random)
}
