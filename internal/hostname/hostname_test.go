package hostname

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serial(s string) (sn [16]byte) {
	copy(sn[:], s)
	return sn
}

func TestRawSerialValidation(t *testing.T) {
	for _, s := range []string{"1234567890ABCDEF", "NAOS-12345678901", "aaaaaaaaaaaaaaaa"} {
		if name, err := serialName(serial(s)); err != nil || name != s {
			t.Fatalf("valid serial %q: name=%q err=%v", s, name, err)
		}
	}
	for _, s := range []string{"", "0000000000000000", "-123456789012345", "123456789012345-", "12345678 0ABCDEF", "12345678.0ABCDEF", "12345678_0ABCDEF", "12345678\x000ABCDEF", "12345678\xff0ABCDEF"} {
		if name, err := serialName(serial(s)); err == nil || name != "" {
			t.Fatalf("invalid raw serial %q accepted as %q", s, name)
		}
	}
}

func TestApplyChangesKernelAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostname")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	want := "1234567890ABCDEF"
	var setName string
	name, err := apply(serial(want), path, func() (string, error) { return "old", nil }, func(b []byte) error { setName = string(b); return nil })
	data, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || name != want || setName != want || string(data) != want+"\n" {
		t.Fatalf("name=%q set=%q data=%q err=%v read=%v", name, setName, data, err, readErr)
	}
}

func TestUnchangedHostnameDoesNotSetOrRewrite(t *testing.T) {
	want := "1234567890ABCDEF"
	path := filepath.Join(t.TempDir(), "hostname")
	if err := os.WriteFile(path, []byte(want+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Unix(100, 0)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	name, err := apply(serial(want), path, func() (string, error) { return want, nil }, func([]byte) error { t.Fatal("unchanged kernel hostname set"); return nil })
	info, statErr := os.Stat(path)
	if err != nil || name != want || statErr != nil || !info.ModTime().Equal(oldTime) {
		t.Fatalf("name=%q err=%v stat=%v", name, err, statErr)
	}
}

func TestPermissionFailureDoesNotPersistOrPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostname")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	name, err := apply(serial("1234567890ABCDEF"), path, func() (string, error) { return "old", nil }, func([]byte) error { return os.ErrPermission })
	data, readErr := os.ReadFile(path)
	if name != "" || !errors.Is(err, os.ErrPermission) || readErr != nil || string(data) != "old\n" {
		t.Fatalf("name=%q data=%q err=%v read=%v", name, data, err, readErr)
	}
}

func TestInvalidSerialDoesNotTouchHostname(t *testing.T) {
	name, err := apply([16]byte{}, "unused", func() (string, error) { t.Fatal("invalid SN read kernel hostname"); return "", nil }, func([]byte) error { t.Fatal("invalid SN set kernel hostname"); return nil })
	if name != "" || err == nil {
		t.Fatalf("invalid SN name=%q err=%v", name, err)
	}
}

func TestPersistenceFailureKeepsAppliedName(t *testing.T) {
	want := "1234567890ABCDEF"
	name, err := apply(serial(want), t.TempDir(), func() (string, error) { return "old", nil }, func([]byte) error { return nil })
	if name != want || err == nil {
		t.Fatalf("applied name=%q err=%v", name, err)
	}
}

func TestUnsupportedPlatformLeavesHostnameAlone(t *testing.T) {
	name, err := Apply("")
	if name != "" || err == nil {
		t.Fatalf("unsupported platform name=%q err=%v", name, err)
	}
}
