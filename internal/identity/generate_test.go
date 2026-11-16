package identity

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"naos.local/core/internal/oem"
)

func TestManualPlatformDetectionUsesOnlyExactHardwareCompatibility(t *testing.T) {
	for _, c := range []struct{ compatible, want string }{
		{"mixtile,core3588e\x00rockchip,rk3588\x00", "rk3588"},
		{"rockchip,rk3506\x00", ""},
		{"vendor,rockchip,rk3588\x00", ""},
		{"rockchip,rk3588s\x00", ""},
		{strings.Repeat("x", 16*1024) + "rockchip,rk3588", ""},
	} {
		t.Run(c.want+"-"+c.compatible[:min(20, len(c.compatible))], func(t *testing.T) {
			got := detectPlatform(func(path string) ([]byte, error) {
				if path != "/proc/device-tree/compatible" && path != "/sys/firmware/devicetree/base/compatible" {
					t.Fatalf("manual registration tried to read %s", path)
				}
				return []byte(c.compatible), nil
			})
			if got != c.want {
				t.Fatalf("platform=%q, want=%q", got, c.want)
			}
		})
	}
}

func TestManualPlatformDetectionFallsBackToSysfsAndUnknown(t *testing.T) {
	got := detectPlatform(func(path string) ([]byte, error) {
		if path == "/proc/device-tree/compatible" {
			return nil, errors.New("fixture unavailable")
		}
		return []byte("rockchip,rk3588\x00"), nil
	})
	if got != "rk3588" {
		t.Fatal(got)
	}
	if got := detectPlatform(func(string) ([]byte, error) { return nil, io.EOF }); got != "" {
		t.Fatal(got)
	}
}

func TestFreshGenerationSharesSerialAndFallbackRules(t *testing.T) {
	read := func(soc string) (oem.Info, error) {
		if soc != "rk3588" {
			return oem.Info{}, oem.ErrUnsupported
		}
		var info oem.Info
		copy(info.SN[:], "MC842H2631000006")
		return info, nil
	}
	id, err := generate("rk3588", "", read, bytes.NewReader(nil))
	if err != nil || id != "SN--MC842H2631000006" {
		t.Fatalf("id=%s, err=%v", id, err)
	}
	id, err = generate("", "", read, bytes.NewReader(make([]byte, 32)))
	if err != nil || id != "NN000000000000000000" {
		t.Fatalf("id=%s, err=%v", id, err)
	}
	if _, err := generate("", "", read, bytes.NewReader(nil)); err == nil {
		t.Fatal("random-source failure was hidden")
	}
}
