package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerStartupConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, body, manifest string
		enabled              bool
		warnings             int
	}{
		{"legacy", "address=/run/custom-naosd.sock\n", "/userdata/manifest.yml", false, 0},
		{"enabled", "enabled=true\nmanifest=/userdata/myapp/manifest.yml\n", "/userdata/myapp/manifest.yml", true, 0},
		{"disabled", "enabled=false\nmanifest=/userdata/myapp/manifest.yml\n", "/userdata/myapp/manifest.yml", false, 0},
		{"defaultManifest", "enabled=true\n", "/userdata/manifest.yml", true, 0},
		{"emptyManifest", "enabled=true\nmanifest=\n", "", false, 1},
		{"invalidEnable", "enabled=yes\nmanifest=/userdata/myapp/manifest.yml\n", "/userdata/myapp/manifest.yml", false, 1},
		{"invalidPath", "enabled=true\nmanifest=/etc/private-startup/manifest.yml\n", "/userdata/manifest.yml", true, 1},
		{"finalEmpty", "enabled=true\nmanifest=/userdata/myapp/manifest.yml\nmanifest=\n", "", false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[container]\n"+test.body+"[core]\nstate_dir=/var/lib/custom-core\n[watchdog]\nenabled=false\n")
			cfg, err := Load(path)
			if err != nil || cfg.ContainerEnabled != test.enabled || cfg.ContainerManifest != test.manifest || len(cfg.Warnings) != test.warnings {
				t.Fatalf("startup configuration: enabled=%v manifest=%q warnings=%v err=%v", cfg.ContainerEnabled, cfg.ContainerManifest, cfg.Warnings, err)
			}
			if cfg.StateDir != "/var/lib/custom-core" || cfg.Watchdog.Enabled {
				t.Fatal("startup configuration discarded unrelated settings")
			}
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "private-startup") {
					t.Fatal("startup warning disclosed a rejected configuration value")
				}
			}
		})
	}
}

func TestContainerManifestPathValidation(t *testing.T) {
	for _, value := range []string{"", "/userdata/manifest.yml", "/userdata/myapp/manifest.yml", "/userdata/my app/manifest.yml"} {
		cfg := defaults()
		if err := assign(&cfg, "container.manifest", value); err != nil || cfg.ContainerManifest != value {
			t.Fatalf("valid manifest path %q: %v", value, err)
		}
	}
	for i, value := range []string{
		"relative/manifest.yml", "/userdata", "/userdata/", "/userdata-other/app/manifest.yml", "/etc/app/manifest.yml",
		"/userdata/app/manifest.yaml", "/userdata/app//manifest.yml", "/userdata/../app/manifest.yml", "/userdata/app/./manifest.yml", "/userdata/app/manifest.yml/",
		"/userdata/app\x00/manifest.yml", "/userdata/app\n/manifest.yml", "/userdata/app\r/manifest.yml", "/userdata/app\t/manifest.yml", "/userdata/app\x7f/manifest.yml", "/userdata/app\u0085/manifest.yml",
		"/userdata/" + strings.Repeat("a", 4096) + "/manifest.yml",
	} {
		cfg := defaults()
		err := assign(&cfg, "container.manifest", value)
		if err == nil || cfg.ContainerManifest != "/userdata/manifest.yml" || !strings.Contains(err.Error(), "container.manifest:") {
			t.Fatalf("invalid manifest path case %d: %v", i, err)
		}
		if err.Error() != "container.manifest: expected a clean /userdata/ path to manifest.yml within the length limit" {
			t.Fatalf("rejected path case %d did not use a redacted warning", i)
		}
	}
}
