package mdns

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func inDirectory(dir string) *Manager {
	return &Manager{directory: dir, hostname: func() (string, error) { return "TEST123456789012", nil }, available: func() error { return nil }}
}

func testManager(t *testing.T) *Manager { t.Helper(); return inDirectory(t.TempDir()) }

func service() Service {
	return Service{Name: "客厅主控", Type: "_mlp._tcp", Port: 1886, TXT: map[string]string{"version": "1", "model": "nano"}}
}

func filename(m *Manager, id string) string {
	return filepath.Join(m.directory, filePrefix+id+fileSuffix)
}

func TestPersistentEscapedXMLAndPermissions(t *testing.T) {
	m := testManager(t)
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)
	s := service()
	s.Name = "客厅 & <设备>"
	s.TXT["description"] = "a&b<c>中文\"quoted\""
	reg, err := m.Put(context.Background(), "mlp", s)
	if err != nil || reg.State != "configured" || reg.Host != "TEST123456789012.local" {
		t.Fatalf("reg=%+v err=%v", reg, err)
	}
	path := filename(m, "mlp")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "&amp;") || !strings.Contains(string(data), "&lt;") {
		t.Fatalf("XML not escaped: %s", data)
	}
	var doc declaration
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Name != s.Name || doc.Services[0].Port != 1886 {
		t.Fatalf("XML=%+v", doc)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("permissions info=%v err=%v", info, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	next := inDirectory(m.directory)
	list, err := next.List(context.Background())
	if err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], reg) {
		t.Fatalf("persisted list=%+v err=%v", list, err)
	}
	if err := next.Delete(context.Background(), "mlp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted file stat=%v", err)
	}
}

func TestEqualPutDoesNotChangeInodeMtimeOrContents(t *testing.T) {
	m := testManager(t)
	if _, err := m.Put(context.Background(), "mlp", service()); err != nil {
		t.Fatal(err)
	}
	path := filename(m, "mlp")
	oldTime := time.Unix(100, 0)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	data, _ := os.ReadFile(path)
	s := service()
	s.Type = "_MLP._TCP"
	s.Host = "test123456789012.LOCAL."
	s.TXT = map[string]string{"model": "nano", "version": "1"}
	if _, err := m.Put(context.Background(), "mlp", s); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	actual, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || !after.ModTime().Equal(oldTime) || string(actual) != string(data) {
		t.Fatal("equivalent Put rewrote the file")
	}
	files, _ := os.ReadDir(m.directory)
	if len(files) != 1 {
		t.Fatalf("temporary files retained: %v", files)
	}
}

func TestRapidUpdatesHaveStrictlyIncreasingMtimeSeconds(t *testing.T) {
	m := testManager(t)
	if _, err := m.Put(context.Background(), "mlp", service()); err != nil {
		t.Fatal(err)
	}
	path := filename(m, "mlp")
	// A future timestamp tests the same-second and backward-clock cases without
	// sleeps or changing the system clock. A third write must advance again.
	stamp := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		s := service()
		s.Port = 1886 + uint16(i)
		if _, err := m.Put(context.Background(), "mlp", s); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.ModTime().Unix() != stamp.Unix()+int64(i) {
			t.Fatalf("update %d mtime=%v", i, info.ModTime())
		}
		list, err := m.List(context.Background())
		if err != nil || len(list) != 1 || list[0].Port != s.Port {
			t.Fatalf("update list=%+v err=%v", list, err)
		}
	}
}

func TestInvalidInputsDoNotCreateFiles(t *testing.T) {
	cases := []struct {
		name, id string
		change   func(*Service)
	}{
		{"empty id", "", nil}, {"path traversal", "../outside", nil}, {"long id", strings.Repeat("a", 65), nil},
		{"empty name", "mlp", func(s *Service) { s.Name = "" }}, {"long unicode name", "mlp", func(s *Service) { s.Name = strings.Repeat("界", 22) }},
		{"zero port", "mlp", func(s *Service) { s.Port = 0 }}, {"numeric type", "mlp", func(s *Service) { s.Type = "_1886._tcp" }},
		{"bad type", "mlp", func(s *Service) { s.Type = "_mlp._tcp.local" }}, {"long type", "mlp", func(s *Service) { s.Type = "_abcdefghijklmnop._tcp" }},
		{"TXT equals", "mlp", func(s *Service) { s.TXT = map[string]string{"a=b": "c"} }}, {"TXT case duplicates", "mlp", func(s *Service) { s.TXT = map[string]string{"Key": "1", "key": "2"} }},
		{"TXT item length", "mlp", func(s *Service) { s.TXT = map[string]string{"a": strings.Repeat("b", 254)} }},
		{"TXT total length", "mlp", func(s *Service) {
			s.TXT = map[string]string{}
			for i := 0; i < 6; i++ {
				s.TXT[fmt.Sprint(i)] = strings.Repeat("b", 200)
			}
		}},
		{"custom hostname", "mlp", func(s *Service) { s.Host = "other.local" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testManager(t)
			s := service()
			if tc.change != nil {
				tc.change(&s)
			}
			if _, err := m.Put(context.Background(), tc.id, s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
			files, _ := os.ReadDir(m.directory)
			if len(files) != 0 {
				t.Fatalf("invalid input wrote %v", files)
			}
		})
	}
	for _, bad := range []string{"\x00", "\r", "\n", "\t", "\x7f", "\u0085", "\ufffe", "\uffff", string([]byte{0xff})} {
		t.Run(fmt.Sprintf("XML text %q", bad), func(t *testing.T) {
			m := testManager(t)
			s := service()
			s.TXT = map[string]string{"text": bad}
			if _, err := m.Put(context.Background(), "mlp", s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("bad TXT accepted err=%v", err)
			}
			s = service()
			s.Name = "name" + bad
			if _, err := m.Put(context.Background(), "mlp", s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("bad name accepted err=%v", err)
			}
		})
	}
}

func TestOnlyOwnFilesAreManaged(t *testing.T) {
	m := testManager(t)
	for _, name := range []string{"ssh.service", "sftp-ssh.service", "custom.service", ".naos-core-temp", "naos-core-.service"} {
		if err := os.WriteFile(filepath.Join(m.directory, name), []byte("keep me"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Put(context.Background(), "mlp", service()); err != nil {
		t.Fatal(err)
	}
	list, err := m.List(context.Background())
	if err != nil || len(list) != 1 || list[0].ID != "mlp" {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := m.Delete(context.Background(), "mlp"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh.service", "sftp-ssh.service", "custom.service", ".naos-core-temp", "naos-core-.service"} {
		data, err := os.ReadFile(filepath.Join(m.directory, name))
		if err != nil || string(data) != "keep me" {
			t.Fatalf("changed unrelated file %s: %v", name, err)
		}
	}
	if err := m.Delete(context.Background(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing err=%v", err)
	}
}

func TestLimitsMissingAvahiAndClosedManager(t *testing.T) {
	m := testManager(t)
	for i := 0; i < maxServices; i++ {
		if _, err := m.Put(context.Background(), fmt.Sprint(i), service()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Put(context.Background(), "extra", service()); !errors.Is(err, ErrConflict) {
		t.Fatalf("limit err=%v", err)
	}
	s := service()
	s.Port = 1887
	if _, err := m.Put(context.Background(), "0", s); err != nil {
		t.Fatalf("update at limit: %v", err)
	}
	m.available = func() error { return os.ErrNotExist }
	if _, err := m.List(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing Avahi list err=%v", err)
	}
	if _, err := m.Put(context.Background(), "0", s); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing Avahi put err=%v", err)
	}
	if err := m.Delete(context.Background(), "0"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing Avahi delete err=%v", err)
	}
	m.available = func() error { return nil }
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.List(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed list err=%v", err)
	}
	list, err := inDirectory(m.directory).List(context.Background())
	if err != nil || len(list) != maxServices {
		t.Fatalf("close removed files list=%v err=%v", list, err)
	}
}

func TestFilesystemFailuresAndSymlinksAreNotFollowed(t *testing.T) {
	m := testManager(t)
	outside := filepath.Join(t.TempDir(), "keep.service")
	if err := os.WriteFile(outside, []byte("keep me"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filename(m, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put(context.Background(), "link", service()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink put err=%v", err)
	}
	if err := m.Delete(context.Background(), "link"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink delete err=%v", err)
	}
	if _, err := m.List(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink list err=%v", err)
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "keep me" {
		t.Fatal("modified symlink target")
	}
	if err := os.Remove(filename(m, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filename(m, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put(context.Background(), "directory", service()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-file put err=%v", err)
	}
	if err := m.Delete(context.Background(), "directory"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-file delete err=%v", err)
	}
	m.directory = filepath.Join(m.directory, "does-not-exist")
	if _, err := m.Put(context.Background(), "mlp", service()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing directory err=%v", err)
	}
}

func TestMalformedStoredFilesAndCanceledRequests(t *testing.T) {
	m := testManager(t)
	if err := os.WriteFile(filename(m, "bad"), []byte("not XML"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.List(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid stored XML err=%v", err)
	}
	if err := m.Delete(context.Background(), "bad"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Put(ctx, "mlp", service()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("canceled err=%v", err)
	}
	list, err := m.List(context.Background())
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list=%+v err=%v", list, err)
	}
}
