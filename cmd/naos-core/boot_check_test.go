package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naos.local/core/internal/config"
)

func TestBootCheckDisabledDoesNotExecuteProgram(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := checkBoot(config.Config{BootCheckProgram: "/does/not/exist"}, &out, &stderr); code != 0 || out.Len()+stderr.Len() != 0 {
		t.Fatalf("disabled boot check executed a program: %d %s", code, stderr.String())
	}
}

func TestBootCheckCLIUsesOnlyProgramExitStatus(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "check.sh")
	ini := filepath.Join(root, "device.ini")
	if err := os.WriteFile(ini, []byte("[boot]\ncheck_enabled=true\ncheck_program="+program+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		script string
		want   int
	}{
		{"#!/bin/sh\necho checked\nexit 0\n", 0},
		{"#!/bin/sh\necho checked\nexit 7\n", 1},
	} {
		if err := os.WriteFile(program, []byte(test.script), 0700); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := helpRun("boot-check", "--config", ini)
		if code != test.want || out != "checked\n" || test.want != 0 && !strings.Contains(stderr, "exit status 7") {
			t.Fatalf("hook exit was not used: code=%d out=%q stderr=%q", code, out, stderr)
		}
	}
}

func TestBootCheckRejectsMisconfigurationAndNonExecutables(t *testing.T) {
	var out, stderr bytes.Buffer
	for _, cfg := range []config.Config{
		{Warnings: []string{"device.ini: boot.check_enabled: expected true or false"}},
		{BootCheckEnabled: true},
		{BootCheckEnabled: true, BootCheckProgram: "/does/not/exist"},
	} {
		if code := checkBoot(cfg, &out, &stderr); code == 0 {
			t.Fatal("invalid boot check would allow confirmation")
		}
	}
	program := filepath.Join(t.TempDir(), "check")
	if err := os.WriteFile(program, []byte("exit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runBootCheck(context.Background(), program, &out, &stderr); err == nil {
		t.Fatal("non-executable check was accepted")
	}
}

func TestBootCheckCancellationStopsCheck(t *testing.T) {
	program := filepath.Join(t.TempDir(), "check.sh")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nexec sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	if err := runBootCheck(ctx, program, &output, &output); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("check ignored cancellation: %v", err)
	}
}
