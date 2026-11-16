package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"naos.local/core/internal/config"
)

type unixConnectionKey struct{}

// IsUnixRequest reports whether Run accepted the request on a Unix socket.
func IsUnixRequest(r *http.Request) bool {
	unix, _ := r.Context().Value(unixConnectionKey{}).(bool)
	return unix
}

func Run(ctx context.Context, cfg config.Config, handler http.Handler) error {
	if cfg.HTTPEnabled {
		host, _, err := net.SplitHostPort(cfg.HTTPListen)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("http.listen must use a numeric loopback address, e.g. 127.0.0.1:8890")
		}
	}
	if !filepath.IsAbs(cfg.Socket) {
		return errors.New("core.socket must be an absolute path")
	}
	var tcp net.Listener
	if cfg.HTTPEnabled {
		var err error
		tcp, err = net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			return err
		}
		defer tcp.Close()
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(cfg.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("core socket path already exists and is not a socket: %s", cfg.Socket)
		}
		conn, dialErr := net.DialTimeout("unix", cfg.Socket, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("another Core server is using the Unix socket")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return dialErr
		}
		if err := os.Remove(cfg.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	local, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return err
	}
	defer local.Close()
	if err := os.Chmod(cfg.Socket, 0600); err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			_, unix := conn.(*net.UnixConn)
			return context.WithValue(ctx, unixConnectionKey{}, unix)
		}}
	done := make(chan error, 2)
	if tcp != nil {
		go func() { done <- srv.Serve(tcp) }()
	}
	go func() { done <- srv.Serve(local) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return err
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
