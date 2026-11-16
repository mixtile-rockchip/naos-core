package container

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
)

func TestChangeOperationsAndRemoteFailure(t *testing.T) {
	for _, operation := range []struct{ action, method, value string }{
		{"start", "Start", "demo-test_1"},
		{"stop", "Stop", "demo-test_1"},
		{"restart", "Restart", "demo-test_1"},
		{"manifest", "Start", "/userdata/business/manifest.yml"},
	} {
		for _, code := range []uint64{0, 5} {
			t.Run(fmt.Sprintf("%s/%d", operation.action, code), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "control.sock")
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					request, err := readFrame(conn)
					var id string
					if err == nil {
						err = fields(request.Payload, func(f field) error {
							if f.number == 1 {
								id, err = textField(f)
								return err
							}
							return nil
						})
					}
					if err == nil && (request.Kind != 1 || request.Method != operation.method || id != operation.value) {
						err = fmt.Errorf("unexpected request: %+v id=%q", request, id)
					}
					if err == nil {
						err = writeFrame(conn, encodedFrame(4, code, nil))
					}
					done <- err
				}()
				client := Client{Socket: path}
				if operation.action == "manifest" {
					err = client.StartManifest(context.Background(), operation.value)
				} else {
					err = client.Change(context.Background(), operation.value, operation.action)
				}
				if (err == nil) != (code == 0) {
					t.Fatalf("code=%d error=%v", code, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStartManifestRejectsUnsafePathsBeforeConnecting(t *testing.T) {
	for _, path := range []string{"", "manifest.yml", "/etc/manifest.yml", "/userdata/../manifest.yml", "/userdata//app/manifest.yml", "/userdata/app/start.sh", "/userdata/app/manifest.yml\x00", "/userdata/app\n/manifest.yml"} {
		if err := (Client{Socket: "/nonexistent"}).StartManifest(context.Background(), path); err == nil || err.Error() != "container manifest must be a clean /userdata/ path ending in manifest.yml" {
			t.Fatalf("unsafe path was sent to the daemon: %q: %v", path, err)
		}
	}
}

func TestChangeRejectsUnsafeIDsBeforeConnecting(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../demo", "/demo", "demo name", "a\n", "中文"} {
		if err := (Client{Socket: "/nonexistent"}).Change(context.Background(), id, "start"); err != ErrInvalidID {
			t.Fatalf("id %q: %v", id, err)
		}
	}
	if ValidID("-id") || !ValidID("demo_1.2-test") {
		t.Fatal("ID validation differs")
	}
}
