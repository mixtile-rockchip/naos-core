package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

func TestRejectsNonlocalListenersBeforeOpeningSocket(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8890", "192.168.202.168:8890", "[::]:8890", "localhost:8890", ""} {
		if err := Run(context.Background(), config.Config{HTTPEnabled: true, HTTPListen: address, Socket: "/tmp/unused-core-test.sock"}, nil); err == nil {
			t.Fatalf("accepted nonnumeric or nonloopback listener %q", address)
		}
	}
	if err := Run(context.Background(), config.Config{HTTPEnabled: true, HTTPListen: "127.0.0.1:0", Socket: "relative.sock"}, nil); err == nil {
		t.Fatal("accepted relative control socket")
	}
}

func TestDisabledHTTPKeepsUnixHealthWithoutOpeningTCP(t *testing.T) {
	for _, mode := range []string{"free TCP port", "occupied TCP port", "invalid ignored address"} {
		t.Run(mode, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer reserved.Close()
			address := reserved.Addr().String()
			if mode != "occupied TCP port" {
				_ = reserved.Close()
			}
			listen := address
			if mode == "invalid ignored address" {
				listen = "not-a-listen-address"
			}
			socket := filepath.Join(t.TempDir(), "core.sock")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopped := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					http.NotFound(w, r)
					return
				}
				_, _ = io.WriteString(w, `{"status":"ok"}`)
			})
			go func() {
				stopped <- Run(ctx, config.Config{HTTPEnabled: false, HTTPListen: listen, Socket: socket}, handler)
			}()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "unix", socket)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			deadline := time.Now().Add(3 * time.Second)
			ready := false
			for time.Now().Before(deadline) {
				response, err := client.Get("http://localhost/healthz")
				if err == nil {
					body, readErr := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if readErr != nil || response.StatusCode != http.StatusOK || string(body) != `{"status":"ok"}` {
						t.Fatal("Unix self-health failed")
					}
					ready = true
					break
				}
				select {
				case err := <-stopped:
					t.Fatalf("server stopped before Unix ready: %v", err)
				default:
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready {
				t.Fatal("Unix HTTP did not start when TCP was disabled")
			}
			if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("Unix socket permissions changed")
			}
			_ = reserved.Close()
			if conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
				_ = conn.Close()
				t.Fatal("Core opened TCP despite http.enabled=false")
			}
			// Retaining the address for an independent listener also proves Core
			// never bound it, even after the previously occupied port became free.
			rebound, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("disabled Core retained the TCP listening address")
			}
			_ = rebound.Close()
			transport.CloseIdleConnections()
			cancel()
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatalf("cancelled server shutdown: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Unix-only server did not shut down")
			}
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("shutdown left the Unix listening socket behind")
			}
		})
	}
}
