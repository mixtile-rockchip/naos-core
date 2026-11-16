package identity

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"naos.local/core/internal/config"
	"naos.local/core/internal/oem"
)

func configuration(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device.ini")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func unavailable(string) (oem.Info, error) { return oem.Info{}, oem.ErrUnsupported }
func rawSerial(sn []byte) func(string) (oem.Info, error) {
	return func(string) (oem.Info, error) { var info oem.Info; copy(info.SN[:], sn); return info, nil }
}
func persisted(t *testing.T, path, id string) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil || cfg.Hawkbit.ControllerID != id {
		t.Fatalf("identity not readable through config.Load: %q %v", cfg.Hawkbit.ControllerID, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("identity configuration is not private: %v %v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "device.ini" {
		t.Fatalf("identity left a sidecar or temporary file: %v %v", entries, err)
	}
}

func TestKnownSerialIsReusedWithoutAnotherOTPRead(t *testing.T) {
	path := configuration(t, "# keep comment\n[hawkbit]\ncontroller_id=\n; identity comment\n[core]\nstate_dir=/var/lib/custom\n")
	id, err := resolve("rk3588", path, "MC842H2631000006", func(string) (oem.Info, error) { t.Fatal("known SN read OTP again"); return oem.Info{}, nil }, bytes.NewReader(nil))
	if err != nil || id != "SN--MC842H2631000006" || len(id) != 20 {
		t.Fatalf("SN identity: %q %v", id, err)
	}
	persisted(t, path, id)
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "keep comment") || !strings.Contains(string(data), "identity comment") {
		t.Fatalf("identity rewrite lost original content: %s", data)
	}
}

func TestRawOTPSerialAndInvalidBytes(t *testing.T) {
	for _, sn := range []string{"MC842H2631000006", "ABCD_1234.56-789"} {
		if len(sn) != 16 {
			continue
		}
		path := configuration(t, "[hawkbit]\ncontroller_id=\n")
		id, err := resolve("rk3588", path, "", rawSerial([]byte(sn)), bytes.NewReader(nil))
		if err != nil || id != "SN--"+sn {
			t.Fatalf("raw OEM identity rejected: %q %v", id, err)
		}
	}
	for _, raw := range [][]byte{make([]byte, 16), bytes.Repeat([]byte{255}, 16), []byte("0000000000000000"), []byte("invalid SN      "), []byte("invalid/SN000000"), []byte("invalid@SN000000"), append([]byte("0123456789ABCDE"), 0)} {
		path := configuration(t, "[hawkbit]\ncontroller_id=\n")
		id, err := resolve("rk3588", path, "", rawSerial(raw), bytes.NewReader(make([]byte, 32)))
		if err != nil || id != "NN000000000000000000" {
			t.Fatalf("invalid raw OTP became a serial ID: %q %v", id, err)
		}
	}
}

func TestRandomIdentityIsPrivateStableAndNotReplacedByLaterSN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "config", "device.ini")
	id, err := resolve("unsupported", path, "", unavailable, rand.Reader)
	if err != nil || !regexp.MustCompile(`^NN[A-Za-z0-9]{18}$`).MatchString(id) {
		t.Fatalf("random identity: %q %v", id, err)
	}
	persisted(t, path, id)
	before, _ := os.ReadFile(path)
	for _, known := range []string{"", "MC842H2631000006"} {
		again, err := resolve("rk3588", path, known, func(string) (oem.Info, error) { t.Fatal("saved identity reread OTP"); return oem.Info{}, nil }, bytes.NewReader(nil))
		if err != nil || again != id {
			t.Fatalf("restart changed identity: %q %v", again, err)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("saved identity rewrote configuration")
	}
}

func TestConfiguredIDSurvivesIncompleteHawkbitCredentials(t *testing.T) {
	for _, body := range []string{
		"[hawkbit]\nenabled=true\ncontroller_id=my-explicit-id\n",
		"[hawkbit]\ncontroller_id=first\n[hawkbit]\ncontroller_id=last-valid\n",
	} {
		path := configuration(t, body)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		id, err := resolve("rk3588", path, "MC842H2631000006", unavailable, bytes.NewReader(nil))
		if err != nil || id != cfg.Hawkbit.ControllerID || id == "" {
			t.Fatalf("configured ID overwritten: %q %v", id, err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != body {
			t.Fatal("explicit identity file was modified")
		}
	}
}

func TestRepeatedSectionsBlankEffectiveIDAndMissingKey(t *testing.T) {
	for _, body := range []string{
		"[hawkbit]\ncontroller_id=old\n# header\n[core]\nstate_dir=/var/lib/custom\n[hawkbit]\ncontroller_id=\n# keep\n[http]\nlisten=127.0.0.1:8890\n",
		"[hawkbit]\nenabled=false\n[core]\nstate_dir=/var/lib/custom\n",
		"[platform]\nsoc=rk3588", "[hawkbit]\r\n; keep\r\ncontroller_id=\r\n",
	} {
		path := configuration(t, body)
		id, err := resolve("rk3588", path, "MC842H2631000006", unavailable, bytes.NewReader(nil))
		if err != nil || id != "SN--MC842H2631000006" {
			t.Fatalf("INI placement failed: %q %v", id, err)
		}
		persisted(t, path, id)
		data, _ := os.ReadFile(path)
		for _, comment := range []string{"header", "keep"} {
			if strings.Contains(body, comment) && !strings.Contains(string(data), comment) {
				t.Fatal("INI comment lost")
			}
		}
	}
}

func TestConcurrentFirstGenerationAgrees(t *testing.T) {
	path := configuration(t, "[hawkbit]\ncontroller_id=\n")
	var group sync.WaitGroup
	results := make(chan string, 24)
	for i := 0; i < 24; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			id, err := resolve("unsupported", path, "", unavailable, rand.Reader)
			if err != nil {
				t.Error(err)
				return
			}
			results <- id
		}()
	}
	group.Wait()
	close(results)
	first := ""
	for id := range results {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatalf("parallel callers disagreed: %q %q", first, id)
		}
	}
	if first == "" {
		t.Fatal("no identity returned")
	}
	persisted(t, path, first)
}

type failedRandom struct{ err error }

func (f failedRandom) Read([]byte) (int, error) { return 0, f.err }

func TestPersistenceAndEntropyErrorsAreNotSwallowed(t *testing.T) {
	path := configuration(t, "# unchanged\n[hawkbit]\ncontroller_id=\n")
	broken := errors.New("entropy unavailable")
	if id, err := resolve("unsupported", path, "", unavailable, failedRandom{broken}); id != "" || !errors.Is(err, broken) {
		t.Fatalf("entropy failure hidden: %q %v", id, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# unchanged\n") || strings.Contains(string(data), "NN") {
		t.Fatal("failed generation changed file")
	}
	link := filepath.Join(t.TempDir(), "device.ini")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("unsupported", link, "", unavailable, rand.Reader); err == nil {
		t.Fatal("symlink identity configuration accepted")
	}
	if _, err := resolve("unsupported", path+"/device.ini", "", unavailable, rand.Reader); err == nil {
		t.Fatal("unwritable configuration parent accepted")
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(filepath.Dir(path), 0700)
		if id, err := resolve("unsupported", path, "", unavailable, rand.Reader); id != "" || err == nil {
			t.Fatal("read-only persistence error hidden")
		}
	}
}

var _ io.Reader = failedRandom{}
