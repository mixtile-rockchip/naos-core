package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"naos.local/core/internal/config"
)

func checkBoot(cfg config.Config, out, stderr io.Writer) int {
	// An invalid opt-in must not silently fall back to a successful check.
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, ": boot.check_") {
			fmt.Fprintln(stderr, "naos-core: invalid boot check configuration")
			return 1
		}
	}
	if !cfg.BootCheckEnabled {
		return 0
	}
	if err := runBootCheck(context.Background(), cfg.BootCheckProgram, out, stderr); err != nil {
		fmt.Fprintln(stderr, "naos-core: boot check:", err)
		return 1
	}
	return 0
}

func runBootCheck(ctx context.Context, program string, out, stderr io.Writer) error {
	if program == "" {
		return errors.New("check_program is required when check_enabled=true")
	}
	info, err := os.Stat(program)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("check_program must be an executable file (scripts need a shebang)")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, program)
	cmd.Stdout, cmd.Stderr = out, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("check did not complete: %w", ctx.Err())
	}
	return err
}
