package main

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// Avahi keeps its own hostname; update it when Core starts after the daemon.
func syncAvahi(name string) error {
	if _, err := os.Stat("/usr/sbin/avahi-daemon"); os.IsNotExist(err) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/dbus-send", "--system", "--print-reply",
		"--reply-timeout=1000", "--dest=org.freedesktop.Avahi", "/",
		"org.freedesktop.Avahi.Server.SetHostName", "string:"+name).Run()
}
