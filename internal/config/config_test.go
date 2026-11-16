package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformMustBeConfiguredInItsOwnSection(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"empty", "", ""},
		{"otherSection", "[device]\nsoc=rk3588\n", ""},
		{"explicit", "# board config\n[platform]\nsoc = rk3588 ; OEM reader\n", "rk3588"},
		{"otherPlatform", "[platform]\nsoc=rk3506\n", "rk3506"},
		{"unrelatedKeys", "[platform]\nsoc=rk3588\nboard=nano\n[http]\nlisten=127.0.0.1:8890\n", "rk3588"},
		{"cleared", "[platform]\nsoc=rk3588\nsoc=\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "device.ini")
			if err := os.WriteFile(path, []byte(c.text), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if err != nil || got.SoC != c.want {
				t.Fatalf("Load: %+v, %v; want soc=%q", got, err, c.want)
			}
		})
	}
}

func TestMissingConfigDisablesPlatformSupport(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.ini"))
	if err != nil || cfg.SoC != "" {
		t.Fatalf("missing file selected a platform: %+v %v", cfg, err)
	}
}

func TestLocalServiceConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.ini")
	if err := os.WriteFile(path, []byte("[platform]\nsoc=rk3588\n[http]\nlisten=127.0.0.1:18890\n[core]\nsocket=/tmp/core.sock\n[container]\naddress=/tmp/naosd.sock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.SoC != "rk3588" || cfg.HTTPListen != "127.0.0.1:18890" || cfg.Socket != "/tmp/core.sock" || cfg.ContainerSocket != "/tmp/naosd.sock" {
		t.Fatalf("configuration not applied: %+v %v", cfg, err)
	}
}

func TestMalformedINIFailsWithoutDisclosingValues(t *testing.T) {
	const secret = "private-token-that-must-not-appear"
	path := filepath.Join(t.TempDir(), "device.ini")
	if err := os.WriteFile(path, []byte("[platform]\nsoc=rk3588\nmalformed "+secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("malformed INI was accepted or disclosed configuration contents")
	}
}

func TestINIRepeatedKeysUseFinalValueAndIndependentFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.ini")
	body := "[platform]\nsoc=rk3588\nsoc=invalid space\n[hawkbit]\ncontroller_id=first\n[hawkbit]\ncontroller_id=last\ntoken=literal%(value)s#part;part\n[core]\nstate_dir=/var/lib/custom\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.SoC != "" || cfg.Hawkbit.ControllerID != "last" || cfg.Hawkbit.Token != "literal%(value)s#part;part" || cfg.StateDir != "/var/lib/custom" || len(cfg.Warnings) != 1 {
		t.Fatal("INI final-value rules, independent fallback or raw token changed")
	}
}
