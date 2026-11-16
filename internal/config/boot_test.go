package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBootCheckConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, body, program string
		enabled             bool
		warnings            int
	}{
		{"defaults", "", "", false, 0},
		{"enabled", "check_enabled=true\ncheck_program=/userdata/boot-check.sh\n", "/userdata/boot-check.sh", true, 0},
		{"disabled", "check_enabled=false\ncheck_program=/usr/bin/application-check\n", "/usr/bin/application-check", false, 0},
		{"missingProgram", "check_enabled=true\n", "", true, 1},
		{"emptyProgram", "check_enabled=true\ncheck_program=\n", "", true, 1},
		{"invalidEnable", "check_enabled=yes\n", "", false, 1},
		{"invalidProgram", "check_enabled=true\ncheck_program=private-value/boot-check\n", "", true, 2},
		{"finalEmpty", "check_enabled=true\ncheck_program=/userdata/boot-check.sh\ncheck_program=\n", "", true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[boot]\n"+test.body+"[core]\nstate_dir=/var/lib/custom-core\n[watchdog]\nenabled=false\n")
			cfg, err := Load(path)
			if err != nil || cfg.BootCheckEnabled != test.enabled || cfg.BootCheckProgram != test.program || len(cfg.Warnings) != test.warnings {
				t.Fatalf("boot check configuration: enabled=%v program=%q warnings=%v err=%v", cfg.BootCheckEnabled, cfg.BootCheckProgram, cfg.Warnings, err)
			}
			if cfg.StateDir != "/var/lib/custom-core" || cfg.Watchdog.Enabled {
				t.Fatal("boot check configuration discarded unrelated settings")
			}
			for _, warning := range cfg.Warnings {
				if !strings.Contains(warning, "boot.check_") || strings.Contains(warning, "private-value") {
					t.Fatal("boot warning cannot be attributed to its field or disclosed a value")
				}
			}
		})
	}
}

func TestBootCheckProgramPathValidation(t *testing.T) {
	for i, value := range []string{"relative", "/", "/usr/bin/../bin/check", "/usr//bin/check", "/userdata/check\x00", "/userdata/check\n", strings.Repeat("/a", 2049)} {
		cfg := defaults()
		err := assign(&cfg, "boot.check_program", value)
		if err == nil || cfg.BootCheckProgram != "" || !strings.HasPrefix(err.Error(), "boot.check_program:") {
			t.Fatalf("invalid program case %d: %v", i, err)
		}
	}
}
