package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"naos.local/core/internal/config"
	"naos.local/core/internal/container"
)

type startupClientStub struct {
	list  func(context.Context) ([]container.State, error)
	start func(context.Context, string) error
}

func (s startupClientStub) List(ctx context.Context) ([]container.State, error) {
	return s.list(ctx)
}

func (s startupClientStub) StartManifest(ctx context.Context, path string) error {
	return s.start(ctx, path)
}

func TestContainerStartupDisabledDoesNotContactDaemon(t *testing.T) {
	var output bytes.Buffer
	// A nil stub would panic if either dependency were contacted.
	err := startConfiguredContainer(context.Background(), config.Config{}, startupClientStub{}, log.New(&output, "", 0))
	if err != nil || output.Len() != 0 {
		t.Fatalf("disabled startup produced work: %v %s", err, output.String())
	}
}

func TestContainerStartupSendsConfiguredManifestOnce(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "ambiguousFailure"}[failure], func(t *testing.T) {
			cfg := config.Config{ContainerEnabled: true, ContainerManifest: "/userdata/app/manifest.yml"}
			var output bytes.Buffer
			var lists, starts int
			injected := errors.New("response lost after sending Start")
			client := startupClientStub{
				list: func(context.Context) ([]container.State, error) { lists++; return nil, nil },
				start: func(ctx context.Context, path string) error {
					starts++
					if lists == 0 || path != cfg.ContainerManifest || ctx.Err() != nil {
						t.Fatal("startup did not wait for readiness or changed the manifest path")
					}
					if failure {
						return injected
					}
					return nil
				},
			}
			err := startConfiguredContainer(context.Background(), cfg, client, log.New(&output, "", 0))
			if lists != 1 || starts != 1 || failure != errors.Is(err, injected) {
				t.Fatalf("startup repeated or lost its result: list=%d start=%d err=%v", lists, starts, err)
			}
			if failure && output.Len() != 0 || !failure && !strings.Contains(output.String(), cfg.ContainerManifest) {
				t.Fatalf("incorrect startup success log: %q", output.String())
			}
		})
	}
}

func TestContainerStartupCanStopWhileWaitingForDaemon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := startupClientStub{list: func(context.Context) ([]container.State, error) {
		cancel()
		return nil, errors.New("socket not ready")
	}}
	started := time.Now()
	err := startConfiguredContainer(ctx, config.Config{ContainerEnabled: true}, client, log.New(&bytes.Buffer{}, "", 0))
	if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatalf("shutdown waited for startup timeout: %v", err)
	}
}
