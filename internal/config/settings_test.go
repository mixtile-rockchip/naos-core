package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeConfig(t *testing.T, path, text string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestShippedCompleteConfiguration(t *testing.T) {
	data, err := os.ReadFile("../../config/device.ini.example")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), string(data)))
	if err != nil {
		t.Fatal(err)
	}
	expected := defaults()
	expected.SoC = "rk3588"
	if !reflect.DeepEqual(cfg, expected) {
		t.Fatalf("complete template differs from built-in defaults: %+v", cfg)
	}
	file, err := readINIFile("../../config/device.ini.example")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, section := range file.Sections() {
		for _, key := range section.Keys() {
			keys[section.Name()+"."+key.Name()] = true
		}
	}
	for _, key := range []string{"platform.soc", "http.enabled", "http.listen", "core.socket", "core.state_dir", "container.address", "container.enabled", "container.manifest", "boot.check_enabled", "boot.check_program", "hawkbit.enabled", "hawkbit.server_url", "hawkbit.tenant", "hawkbit.controller_id", "hawkbit.token", "hawkbit.token_type", "hawkbit.poll_interval", "hawkbit.timeout", "hawkbit.download_path", "watchdog.enabled", "watchdog.device", "watchdog.timeout", "watchdog.feed_interval"} {
		if !keys[key] {
			t.Errorf("complete user template omits %s", key)
		}
	}
}

func TestSingleFileValuesAndSecretCommentCharacters(t *testing.T) {
	text := `[core]
state_dir=/var/lib/device-core
[http]
listen=[::1]:8891
[hawkbit]
enabled=true
server_url=https://updates.example.test/
tenant=DEFAULT
controller_id=SN0001
token=private#part;part
poll_interval=3m
timeout=12s
download_path=/userdata/downloads
[watchdog]
enabled=false
`
	cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), text))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 0 || !cfg.Hawkbit.Enabled || cfg.Hawkbit.Token != "private#part;part" || cfg.Hawkbit.ServerURL != "https://updates.example.test" || cfg.Hawkbit.PollInterval != 3*time.Minute || cfg.Hawkbit.Timeout != 12*time.Second || cfg.Watchdog.Enabled || cfg.HTTPListen != "[::1]:8891" || cfg.StateDir != "/var/lib/device-core" {
		t.Fatalf("single configuration did not preserve valid fields: %+v", cfg)
	}
}

func TestInvalidOverridesWarnWithoutValuesAndContinue(t *testing.T) {
	const secret = "sensitive-token-that-must-not-appear"
	text := "[hawkbit]\ntoken=" + secret + " invalid\nunknown_credential=" + secret + "\n[http]\nlisten=0.0.0.0:8890\n[platform]\nsoc=rk3506\n"
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), text)
	cfg, err := Load(path)
	if err != nil || len(cfg.Warnings) != 3 || cfg.SoC != "rk3506" || cfg.Hawkbit.Token != "" || cfg.HTTPListen != "127.0.0.1:8890" {
		t.Fatalf("override recovery failed: %+v %v", cfg, err)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, secret) || !strings.Contains(warning, path+":") {
			t.Fatalf("warning leaks value or loses location: %s", warning)
		}
	}

}

func TestOnlySelectedConfigurationIsRead(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "defaults.ini"), "[platform]\nsoc=unselected\n[watchdog]\nenabled=false\n")
	chosen := writeConfig(t, filepath.Join(root, "selected.ini"), "[platform]\nsoc=rk3506\n")
	cfg, err := Load(chosen)
	if err != nil || cfg.SoC != "rk3506" || !cfg.Watchdog.Enabled || cfg.Hawkbit.Enabled {
		t.Fatalf("selected file did not retain independent fallback: %+v %v", cfg, err)
	}
	cfg, err = Load(filepath.Join(root, "missing.ini"))
	if err != nil || cfg.SoC != "" || !cfg.Watchdog.Enabled || cfg.StateDir != "/var/lib/naos-core" {
		t.Fatalf("missing selected file read another configuration: %+v %v", cfg, err)
	}
}

func TestLegacyFourFieldsKeepNewDefaults(t *testing.T) {
	text := "[platform]\nsoc=rk3588\n[http]\nlisten=127.0.0.1:18890\n[core]\nsocket=/run/naos/legacy-core.sock\n[container]\naddress=/run/naos/legacy-daemon.sock\n"
	cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "legacy.ini"), text))
	expected := defaults()
	expected.SoC = "rk3588"
	expected.HTTPListen = "127.0.0.1:18890"
	expected.Socket = "/run/naos/legacy-core.sock"
	expected.ContainerSocket = "/run/naos/legacy-daemon.sock"
	if err != nil || !reflect.DeepEqual(cfg, expected) {
		t.Fatalf("legacy fields discarded new defaults: %+v %v", cfg, err)
	}
}

func TestHawkbitAutomaticIDAndExplicitIDWithMissingCredentials(t *testing.T) {
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[hawkbit]\nenabled=true\nserver_url=https://updates.example.test\ntenant=DEFAULT\ntoken=valid-token\ncontroller_id=\n")
	cfg, err := Load(path)
	if err != nil || !cfg.Hawkbit.Enabled || cfg.Hawkbit.ControllerID != "" || len(cfg.Warnings) != 0 {
		t.Fatalf("automatic ID mode disabled valid hawkbit: %+v %v", cfg, err)
	}
	path = writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[hawkbit]\nenabled=true\ncontroller_id=keep-this-id\n")
	cfg, err = Load(path)
	if err != nil || cfg.Hawkbit.Enabled || cfg.Hawkbit.ControllerID != "keep-this-id" || len(cfg.Warnings) != 1 {
		t.Fatalf("missing credentials discarded explicit identity: %+v %v", cfg, err)
	}
}

func TestRelatedOverrideErrorsKeepOtherSettings(t *testing.T) {
	text := "[watchdog]\nenabled=false\ntimeout=5s\nfeed_interval=9s\n[hawkbit]\nenabled=true\n[core]\nstate_dir=/var/lib/custom-core\n"
	cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), text))
	if err != nil || cfg.Watchdog.Enabled || cfg.Watchdog.Timeout != 30*time.Second || cfg.Hawkbit.Enabled || cfg.StateDir != "/var/lib/custom-core" || len(cfg.Warnings) != 2 {
		t.Fatalf("cross-field errors discarded unrelated overrides: %+v %v", cfg, err)
	}

}

func TestValueBoundsAndPaths(t *testing.T) {
	cases := []struct{ section, key, value string }{
		{"core", "state_dir", "/"}, {"core", "socket", "relative"}, {"container", "address", "/run/../tmp/socket"},
		{"http", "listen", "localhost:8890"}, {"http", "listen", "127.0.0.1:0"}, {"http", "listen", "127.0.0.1:65536"},
		{"watchdog", "device", "/dev/watchdog"}, {"watchdog", "device", "/dev/watchdog0/other"},
		{"watchdog", "timeout", "30.5s"}, {"watchdog", "timeout", "301s"}, {"watchdog", "feed_interval", "0s"},
		{"hawkbit", "poll_interval", "25h"}, {"hawkbit", "timeout", "0s"}, {"hawkbit", "enabled", "yes"},
		{"hawkbit", "server_url", "https://user:password@example.test"}, {"hawkbit", "server_url", "ftp://example.test"},
		{"hawkbit", "server_url", "https://example.test?token=secret"}, {"hawkbit", "token", strings.Repeat("x", 1025)},
		{"hawkbit", "controller_id", "path/segment"}, {"hawkbit", "download_path", "relative"},
		{"hawkbit", "token_type", "unsupported-secret"},
	}
	for _, test := range cases {
		t.Run(test.section+"."+test.key+test.value[:min(len(test.value), 16)], func(t *testing.T) {
			path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "["+test.section+"]\n"+test.key+"="+test.value+"\n")
			cfg, err := Load(path)
			if err != nil || len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], test.section+"."+test.key) {
				t.Fatalf("invalid field did not safely warn: %v %v", cfg.Warnings, err)
			}
		})
	}
}

func TestTokenTypeAndExplicitControllerIdentity(t *testing.T) {
	for _, tokenType := range []string{"", "target", "gateway"} {
		text := "[platform]\nsoc=rk3588\n[hawkbit]\ncontroller_id=explicit-controller\n"
		if tokenType != "" {
			text += "token_type=" + tokenType + "\n"
		}
		cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), text))
		want := tokenType
		if want == "" {
			want = "target"
		}
		if err != nil || cfg.Hawkbit.TokenType != want || cfg.Hawkbit.ControllerID != "explicit-controller" || len(cfg.Warnings) != 0 {
			t.Fatalf("token type or explicit identity changed: %+v %v", cfg, err)
		}
	}
	const invalid = "sensitive-invalid-token-type"
	cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[platform]\nsoc=rk3588\n[hawkbit]\ntoken_type="+invalid+"\n"))
	if err != nil || cfg.Hawkbit.TokenType != "target" || cfg.Hawkbit.ControllerID != "" || len(cfg.Warnings) != 1 || strings.Contains(cfg.Warnings[0], invalid) {
		t.Fatalf("invalid token type leaked or selected an automatic identity: %v %v", cfg.Warnings, err)
	}
}

func TestMissingConfigurationFallsBackAndOversizeFails(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.ini"))
	if err != nil || !reflect.DeepEqual(cfg, defaults()) {
		t.Fatalf("optional configuration did not use built-ins: %+v %v", cfg, err)
	}
	path := writeConfig(t, filepath.Join(t.TempDir(), "oversize.ini"), strings.Repeat("#", maximumConfigBytes+1))
	if _, err := Load(path); err == nil {
		t.Fatal("oversize configuration accepted")
	}
}

func TestConcurrentLoadsHaveIndependentWarnings(t *testing.T) {
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[platform]\nsoc=rk3588\nunknown_key=value\n")
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			cfg, err := Load(path)
			if err != nil || cfg.SoC != "rk3588" || len(cfg.Warnings) != 1 {
				t.Errorf("concurrent load differs: %v %v", cfg.Warnings, err)
			}
		}()
	}
	group.Wait()
}

func TestHTTPAndWatchdogEnablementRemainIndependent(t *testing.T) {
	cases := []struct {
		name, text     string
		http, watchdog bool
		warnings       int
	}{
		{"defaults", "", true, true, 0},
		{"http true watchdog false", "[http]\nenabled=true\n[watchdog]\nenabled=false\n", true, false, 0},
		{"http false watchdog true", "[http]\nenabled=false\n[watchdog]\nenabled=true\n", false, true, 0},
		{"both false", "[http]\nenabled=false\n[watchdog]\nenabled=false\n", false, false, 0},
		{"invalid strict boolean", "[http]\nenabled=secret-invalid-boolean\n[watchdog]\nenabled=false\n", true, false, 1},
		{"uppercase rejected", "[http]\nenabled=True\n", true, true, 1},
		{"disabled invalid listen falls back", "[http]\nenabled=false\nlisten=0.0.0.0:8890\n", false, true, 1},
	}
	for _, fixture := range cases {
		t.Run(fixture.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), fixture.text))
			if err != nil || cfg.HTTPEnabled != fixture.http || cfg.Watchdog.Enabled != fixture.watchdog || len(cfg.Warnings) != fixture.warnings || cfg.HTTPListen != defaults().HTTPListen {
				t.Fatalf("independent switches changed: http=%v watchdog=%v warnings=%v err=%v", cfg.HTTPEnabled, cfg.Watchdog.Enabled, cfg.Warnings, err)
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "secret-invalid-boolean") {
					t.Fatal("invalid switch warning exposed its raw value")
				}
			}
		})
	}
}
