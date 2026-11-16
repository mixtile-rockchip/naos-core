package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"naos.local/core/internal/config"
)

func TestCLIUsesCoreSocketForAllControlCommands(t *testing.T) {
	cases := []struct {
		command          string
		args             []string
		id, method, path string
	}{
		{"update", []string{"/userdata/update.raucb"}, "request-1", "POST", "/v1/update"},
		{"tasks", nil, "", "GET", "/v1/update-tasks"},
		{"task", []string{"task-1"}, "", "GET", "/v1/update-tasks/task-1"},
		{"hawkbit", nil, "", "GET", "/v1/hawkbit"},
		{"containers", []string{"start", "demo"}, "", "POST", "/v1/containers/demo/start"},
		{"containers", []string{"stop", "demo"}, "", "POST", "/v1/containers/demo/stop"},
		{"containers", []string{"restart", "demo"}, "", "POST", "/v1/containers/demo/restart"},
	}
	for _, c := range cases {
		t.Run(c.command+c.path, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			observed := make(chan error, 1)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != c.method || r.URL.Path != c.path {
					t.Errorf("request=%s %s", r.Method, r.URL.Path)
				}
				if c.command == "update" {
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["path"] != c.args[0] || body["request_id"] != c.id {
						t.Errorf("update body=%v,error=%v", body, err)
					}
				}
				_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
			})}
			go func() { observed <- server.Serve(listener) }()
			var out, stderr bytes.Buffer
			if code := call(config.Config{Socket: path}, c.command, c.args, c.id, &out, &stderr); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, &stderr)
			}
			_ = server.Close()
			<-observed
		})
	}
}
