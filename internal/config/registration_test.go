package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func registrationProfile() HawkbitConfig {
	return HawkbitConfig{ServerURL: "https://new.example.test/", Tenant: "NEW_TENANT", ControllerID: "NN1234567890abcdefgh", Token: "new-gateway-token", TokenType: "gateway"}
}

func assertSavedRegistration(t *testing.T, path string, want HawkbitConfig) Config {
	t.Helper()
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Hawkbit
	if !got.Enabled || got.ServerURL != strings.TrimRight(want.ServerURL, "/") || got.Tenant != want.Tenant || got.ControllerID != want.ControllerID || got.Token != want.Token || got.TokenType != "gateway" {
		t.Fatal("saved registration differs from the supplied profile")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("configuration must have private permissions: %v %v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".device.ini-") {
			t.Fatal("temporary registration file was left behind")
		}
	}
	return cfg
}

func TestSaveHawkbitRegistrationPreservesOtherSettings(t *testing.T) {
	const input = "# device configuration\n[platform]\nsoc=rk3506\n[hawkbit]\nenabled=false # cloud polling\nserver_url=https://old.example.test\ntenant=OLD\ncontroller_id=old-id\ntoken=old-private-token ; credential comment\ntoken_type=target\npoll_interval=7m\ntimeout=12s\ndownload_path=/userdata/downloads\n[watchdog]\nenabled=false\ntimeout=40s\nfeed_interval=11s\n[core]\nstate_dir=/var/lib/custom\n"
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), input)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	profile := registrationProfile()
	if err := SaveHawkbitRegistration(path, profile); err != nil {
		t.Fatal(err)
	}
	cfg := assertSavedRegistration(t, path, profile)
	if cfg.SoC != "rk3506" || cfg.Watchdog.Enabled || cfg.Hawkbit.PollInterval != 7*time.Minute || cfg.Hawkbit.Timeout != 12*time.Second || cfg.Hawkbit.DownloadPath != "/userdata/downloads" || cfg.Watchdog.Timeout != 40*time.Second || cfg.Watchdog.FeedInterval != 11*time.Second || cfg.StateDir != "/var/lib/custom" || len(cfg.Warnings) != 0 {
		t.Fatal("registration changed an unrelated setting")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, retained := range []string{"device configuration", "cloud polling", "credential comment"} {
		if !strings.Contains(string(data), retained) {
			t.Fatalf("registration discarded retained text %q", retained)
		}
	}
	if strings.Contains(string(data), "old-private-token") {
		t.Fatal("superseded token remains in configuration")
	}
}

func TestSaveHawkbitRegistrationRepeatedSectionsAndComments(t *testing.T) {
	const input = "[hawkbit] # first\r\n token =old-token-one # first credential\r\ncontroller_id=old-one\r\n[platform]\r\nsoc=rk3588\r\n[hawkbit] ; last\r\n token =old-token-two ; second credential\r\ncontroller_id=old-two\r\nenabled=true\r\n[watchdog]\r\nenabled=false\r\n"
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), input)
	profile := registrationProfile()
	if err := SaveHawkbitRegistration(path, profile); err != nil {
		t.Fatal(err)
	}
	cfg := assertSavedRegistration(t, path, profile)
	if !cfg.Hawkbit.Enabled || cfg.Watchdog.Enabled || cfg.SoC != "rk3588" || len(cfg.Warnings) != 0 {
		t.Fatal("repeated sections changed unrelated configuration")
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	if strings.Contains(text, "old-token-") || strings.Contains(text, "old-one") || strings.Contains(text, "old-two") {
		t.Fatal("repeated registration values were not all replaced")
	}
	for _, retained := range []string{"last", "second credential"} {
		if !strings.Contains(text, retained) {
			t.Fatalf("INI comment text was not preserved: %q", retained)
		}
	}
}

func TestSaveHawkbitRegistrationMissingFileOrSection(t *testing.T) {
	for _, text := range []string{"", "# retained\n[platform]\nsoc=rk3588", "[hawkbit]\nenabled=false\n"} {
		t.Run(fmt.Sprint(len(text)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "new", "device.ini")
			if text != "" {
				writeConfig(t, path, text)
			}
			profile := registrationProfile()
			profile.TokenType = "" // The registration save always writes gateway.
			if err := SaveHawkbitRegistration(path, profile); err != nil {
				t.Fatal(err)
			}
			assertSavedRegistration(t, path, profile)
		})
	}
}

func TestSaveHawkbitRegistrationRejectsInvalidProfileWithoutDisclosure(t *testing.T) {
	const marker = "private-registration-secret"
	tests := []struct {
		name string
		edit func(*HawkbitConfig)
	}{
		{"server newline", func(p *HawkbitConfig) { p.ServerURL = "https://example.test/\n" + marker }},
		{"tenant newline", func(p *HawkbitConfig) { p.Tenant = "TENANT\n" + marker }},
		{"id newline", func(p *HawkbitConfig) { p.ControllerID = "ID\r\n" + marker }},
		{"token newline", func(p *HawkbitConfig) { p.Token = marker + "\n" }},
		{"token whitespace", func(p *HawkbitConfig) { p.Token = marker + " # injected" }},
		{"token type", func(p *HawkbitConfig) { p.TokenType = "target" }},
		{"missing tenant", func(p *HawkbitConfig) { p.Tenant = "" }},
		{"missing token", func(p *HawkbitConfig) { p.Token = "" }},
		{"missing id", func(p *HawkbitConfig) { p.ControllerID = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const original = "[hawkbit]\nenabled=false\ntoken=retained-token\n"
			path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), original)
			profile := registrationProfile()
			test.edit(&profile)
			err := SaveHawkbitRegistration(path, profile)
			if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "retained-token") {
				t.Fatal("invalid profile was accepted or disclosed")
			}
			data, _ := os.ReadFile(path)
			if string(data) != original {
				t.Fatal("invalid profile changed the configuration")
			}
		})
	}
}

func TestSaveHawkbitRegistrationSizeAndFileFailures(t *testing.T) {
	profile := registrationProfile()
	for _, size := range []int{maximumConfigBytes + 1, maximumConfigBytes - 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := "[extra]\npadding=" + strings.Repeat("x", size-len("[extra]\npadding="))
			path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), original)
			if err := SaveHawkbitRegistration(path, profile); err == nil {
				t.Fatal("configuration size limit was not enforced")
			}
			data, _ := os.ReadFile(path)
			if string(data) != original {
				t.Fatal("size failure changed the configuration")
			}
		})
	}
	root := t.TempDir()
	target := writeConfig(t, filepath.Join(root, "target.ini"), "# untouched\n")
	link := filepath.Join(root, "device.ini")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveHawkbitRegistration(link, profile); err == nil {
		t.Fatal("symlink configuration accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "# untouched\n" {
		t.Fatal("symlink target was changed")
	}
	if err := SaveHawkbitRegistration(root, profile); err == nil {
		t.Fatal("directory configuration accepted")
	}
	if err := SaveHawkbitRegistration(filepath.Join(target, "device.ini"), profile); err == nil {
		t.Fatal("non-directory parent accepted")
	}
	if os.Geteuid() != 0 {
		private := filepath.Join(root, "readonly")
		if err := os.Mkdir(private, 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(private, 0700)
		if err := SaveHawkbitRegistration(filepath.Join(private, "device.ini"), profile); err == nil {
			t.Fatal("write failure was hidden")
		}
	}
}

func TestSaveHawkbitRegistrationUsesIdentityDirectoryLock(t *testing.T) {
	root := t.TempDir()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
	done := make(chan error, 1)
	go func() { done <- SaveHawkbitRegistration(filepath.Join(root, "device.ini"), registrationProfile()) }()
	select {
	case err := <-done:
		t.Fatalf("registration bypassed the identity directory lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not resume after the directory was unlocked")
	}
}

func TestConcurrentRegistrationsSaveWholeProfiles(t *testing.T) {
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "# keep\n[watchdog]\nenabled=false\n")
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			profile := registrationProfile()
			profile.Tenant, profile.ControllerID, profile.Token = fmt.Sprintf("tenant%d", i), fmt.Sprintf("id%d", i), fmt.Sprintf("gateway-token-%d", i)
			if err := SaveHawkbitRegistration(path, profile); err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	cfg, err := Load(path)
	if err != nil || !cfg.Hawkbit.Enabled || cfg.Watchdog.Enabled || len(cfg.Warnings) != 0 {
		t.Fatalf("concurrent saves lost unrelated settings: %v", err)
	}
	i := strings.TrimPrefix(cfg.Hawkbit.Tenant, "tenant")
	if cfg.Hawkbit.ControllerID != "id"+i || cfg.Hawkbit.Token != "gateway-token-"+i {
		t.Fatal("concurrent registration mixed different profiles")
	}
}

func TestSaveHawkbitRegistrationRejectsMalformedINIWithoutChangingIt(t *testing.T) {
	const secret = "private-old-token"
	body := "[hawkbit]\ntoken=" + secret + "\nmalformed " + secret + "\n"
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), body)
	err := SaveHawkbitRegistration(path, registrationProfile())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("malformed existing INI was accepted or disclosed")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != body {
		t.Fatal("failed registration save changed malformed existing INI")
	}
}

func TestSaveHawkbitRegistrationKeepsLiteralTokens(t *testing.T) {
	path := writeConfig(t, filepath.Join(t.TempDir(), "device.ini"), "[hawkbit]\nenabled=false\n")
	profile := registrationProfile()
	profile.Token = "literal#part;part%(value)s"
	if err := SaveHawkbitRegistration(path, profile); err != nil {
		t.Fatal(err)
	}
	assertSavedRegistration(t, path, profile)
}
