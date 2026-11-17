package systeminfo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFirmwareMetadata(t *testing.T) {
	full := Info{Version: "1.2.3", BuildID: "build-123", Machine: "example-board"}
	cases := []struct {
		name, data string
		want       Info
		wantErr    bool
	}{
		{"full", `{"version":"1.2.3","build_id":"build-123","machine":"example-board","profile":"production","features":{"encrypted":true}}`, full, false},
		{"versionOnly", `{"version":"1.2.3"}`, Info{Version: "1.2.3"}, false},
		{"whitespace", "{\"version\":\" 1.2.3 \",\"build_id\":\" build-123 \",\"machine\":\" example-board \"}\n", full, false},
		{"empty", "", Info{}, true},
		{"null", "null", Info{}, true},
		{"missingVersion", `{"build_id":"build-123","machine":"example-board"}`, Info{}, true},
		{"emptyVersion", `{"version":" \t"}`, Info{}, true},
		{"malformed", `{"version":`, Info{}, true},
		{"wrongVersionType", `{"version":123}`, Info{}, true},
		{"wrongBuildIDType", `{"version":"1.2.3","build_id":123}`, Info{}, true},
		{"wrongMachineType", `{"version":"1.2.3","machine":[]}`, Info{}, true},
		{"trailingJSON", `{"version":"1.2.3"} {}`, Info{}, true},
		{"sizeLimit", `{"version":"1.2.3"}` + strings.Repeat(" ", maxMetadataSize-len(`{"version":"1.2.3"}`)), Info{Version: "1.2.3"}, false},
		{"oversize", `{"version":"1.2.3"}` + strings.Repeat(" ", maxMetadataSize), Info{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "version.json")
			if err := os.WriteFile(path, []byte(c.data), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := read(path)
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("read() = %+v, %v; want %+v, error=%v", got, err, c.want, c.wantErr)
			}
		})
	}
}

func TestReadMissingOrUnreadableMetadata(t *testing.T) {
	dir := t.TempDir()
	if got, err := read(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) || got != (Info{}) {
		t.Fatalf("missing metadata = %+v, %v", got, err)
	}
	if got, err := read(dir); err == nil || got != (Info{}) {
		t.Fatalf("unreadable metadata = %+v, %v", got, err)
	}
}

func TestReadDoesNotCacheFirmwareVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version.json")
	for _, version := range []string{"1.2.3", "1.2.4"} {
		if err := os.WriteFile(path, []byte(`{"version":"`+version+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := read(path); err != nil || got.Version != version {
			t.Fatalf("read() = %+v, %v; want version %q", got, err, version)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := read(path); err == nil || got != (Info{}) {
		t.Fatalf("removed metadata returned a cached version: %+v, %v", got, err)
	}
}
