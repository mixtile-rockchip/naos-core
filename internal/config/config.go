// Package config reads one device INI, with built-in values for missing fields.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"naos.local/core/internal/container"
)

const (
	DefaultPath        = "/etc/naos-core/device.ini"
	DefaultSocket      = "/run/naos/core.sock"
	maximumConfigBytes = 64 * 1024
)

type HawkbitConfig struct {
	Enabled                                bool
	ServerURL, Tenant, ControllerID, Token string
	TokenType                              string
	PollInterval, Timeout                  time.Duration
	DownloadPath                           string
}

type WatchdogConfig struct {
	Enabled               bool
	Device                string
	Timeout, FeedInterval time.Duration
}

type Config struct {
	SoC               string
	HTTPEnabled       bool
	HTTPListen        string
	Socket            string
	ContainerSocket   string
	ContainerEnabled  bool
	ContainerManifest string
	BootCheckEnabled  bool
	BootCheckProgram  string
	StateDir          string
	Hawkbit           HawkbitConfig
	Watchdog          WatchdogConfig
	// Warnings never contain configuration values, including platform tokens.
	Warnings []string
}

func defaults() Config {
	return Config{
		HTTPEnabled: true, HTTPListen: "127.0.0.1:8890", Socket: DefaultSocket,
		ContainerSocket: "/var/run/naosd.sock", ContainerManifest: "/userdata/manifest.yml", StateDir: "/var/lib/naos-core",
		Hawkbit:  HawkbitConfig{TokenType: "target", PollInterval: 4 * time.Minute, Timeout: 30 * time.Second, DownloadPath: "/var/lib/naos-core/downloads"},
		Watchdog: WatchdogConfig{Enabled: true, Device: "/dev/watchdog0", Timeout: 30 * time.Second, FeedInterval: 10 * time.Second},
	}
}

// Load reads only path. Missing or invalid fields retain built-in values with
// redacted warnings. Invalid INI syntax fails without disclosing its contents.
func Load(path string) (Config, error) {
	return loadOverride(defaults(), path)
}

func loadOverride(base Config, path string) (Config, error) {
	file, err := readINIFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := configurationFromINI(base, path, file)
	if cfg.Watchdog.FeedInterval >= cfg.Watchdog.Timeout {
		cfg.Warnings = append(cfg.Warnings, path+": watchdog feed_interval must be shorter than timeout; timing overrides skipped")
		cfg.Watchdog.FeedInterval, cfg.Watchdog.Timeout = base.Watchdog.FeedInterval, base.Watchdog.Timeout
	}
	if cfg.Hawkbit.Enabled && !hawkbitComplete(cfg.Hawkbit) {
		cfg.Warnings = append(cfg.Warnings, path+": enabled hawkbit requires server_url, tenant and token; hawkbit disabled")
		cfg.Hawkbit.Enabled = false
	}
	if cfg.ContainerEnabled && cfg.ContainerManifest == "" {
		cfg.Warnings = append(cfg.Warnings, path+": enabled container requires manifest; container startup disabled")
		cfg.ContainerEnabled = false
	}
	if cfg.BootCheckEnabled && cfg.BootCheckProgram == "" {
		cfg.Warnings = append(cfg.Warnings, path+": boot.check_program: required when boot.check_enabled is true")
	}
	return cfg, nil
}

func configurationFromINI(base Config, path string, file *ini.File) Config {
	cfg := base
	for _, section := range file.Sections() {
		if section.Name() == ini.DefaultSection && len(section.Keys()) == 0 {
			continue
		}
		if !knownSection(section.Name()) {
			cfg.Warnings = append(cfg.Warnings, path+": unknown configuration section")
			continue
		}
		for _, key := range section.Keys() {
			// Value deliberately avoids the INI library's interpolation feature.
			if err := assign(&cfg, section.Name()+"."+key.Name(), key.Value()); err != nil {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: %s", path, err))
			}
		}
	}
	return cfg
}

func knownSection(section string) bool {
	switch section {
	case "platform", "http", "core", "container", "boot", "hawkbit", "watchdog":
		return true
	}
	return false
}

func assign(cfg *Config, key, value string) error {
	bad := func(reason string) error { return fmt.Errorf("%s: %s", key, reason) }
	setBool := func(target *bool) error {
		if value != "true" && value != "false" {
			return bad("expected true or false")
		}
		*target = value == "true"
		return nil
	}
	setPath := func(target *string, socket bool) error {
		limit := 4096
		if socket {
			limit = 107
		}
		if value == "/" || !filepath.IsAbs(value) || filepath.Clean(value) != value || len(value) > limit || strings.ContainsAny(value, "\x00\r\n") {
			return bad("expected a clean absolute path within the length limit")
		}
		*target = value
		return nil
	}
	setDuration := func(target *time.Duration, minimum, maximum time.Duration, seconds bool) error {
		duration, err := time.ParseDuration(value)
		if err != nil || duration < minimum || duration > maximum || (seconds && duration%time.Second != 0) {
			return bad("duration is outside the supported range")
		}
		*target = duration
		return nil
	}
	switch key {
	case "platform.soc":
		if !identifier(value, 64) {
			return bad("invalid platform identifier")
		}
		cfg.SoC = value
	case "http.enabled":
		return setBool(&cfg.HTTPEnabled)
	case "http.listen":
		host, port, err := net.SplitHostPort(value)
		number, portErr := strconv.Atoi(port)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || portErr != nil || number < 1 || number > 65535 {
			return bad("expected a numeric loopback address and port 1..65535")
		}
		cfg.HTTPListen = value
	case "core.socket":
		return setPath(&cfg.Socket, true)
	case "core.state_dir":
		return setPath(&cfg.StateDir, false)
	case "container.address":
		return setPath(&cfg.ContainerSocket, true)
	case "container.enabled":
		return setBool(&cfg.ContainerEnabled)
	case "container.manifest":
		if value != "" && !container.ValidManifestPath(value) {
			return bad("expected a clean /userdata/ path to manifest.yml or /var/lib/naos/containers/<id>/manifest.yml within the length limit")
		}
		cfg.ContainerManifest = value
	case "boot.check_enabled":
		return setBool(&cfg.BootCheckEnabled)
	case "boot.check_program":
		if value == "" {
			cfg.BootCheckProgram = ""
			return nil
		}
		return setPath(&cfg.BootCheckProgram, false)
	case "watchdog.enabled":
		return setBool(&cfg.Watchdog.Enabled)
	case "watchdog.device":
		if !strings.HasPrefix(value, "/dev/watchdog") || value == "/dev/watchdog" || strings.Trim(value[len("/dev/watchdog"):], "0123456789") != "" {
			return bad("expected an explicit /dev/watchdogN node")
		}
		cfg.Watchdog.Device = value
	case "watchdog.timeout":
		return setDuration(&cfg.Watchdog.Timeout, time.Second, 5*time.Minute, true)
	case "watchdog.feed_interval":
		return setDuration(&cfg.Watchdog.FeedInterval, time.Second, time.Minute, false)
	case "hawkbit.enabled":
		return setBool(&cfg.Hawkbit.Enabled)
	case "hawkbit.server_url":
		if value != "" {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(value) > 2048 {
				return bad("expected an HTTP(S) server URL without credentials, query or fragment")
			}
		}
		cfg.Hawkbit.ServerURL = strings.TrimRight(value, "/")
	case "hawkbit.tenant", "hawkbit.controller_id":
		if !identifier(value, 128) {
			return bad("invalid device identity")
		}
		if key == "hawkbit.tenant" {
			cfg.Hawkbit.Tenant = value
		} else {
			cfg.Hawkbit.ControllerID = value
		}
	case "hawkbit.token":
		if len(value) > 1024 {
			return bad("credential exceeds length limit")
		}
		for _, char := range value {
			if char < 33 || char > 126 {
				return bad("credential must use visible ASCII without whitespace")
			}
		}
		cfg.Hawkbit.Token = value
	case "hawkbit.token_type":
		if value != "target" && value != "gateway" {
			return bad("expected target or gateway")
		}
		cfg.Hawkbit.TokenType = value
	case "hawkbit.poll_interval":
		return setDuration(&cfg.Hawkbit.PollInterval, time.Second, 24*time.Hour, false)
	case "hawkbit.timeout":
		return setDuration(&cfg.Hawkbit.Timeout, time.Second, 5*time.Minute, false)
	case "hawkbit.download_path":
		return setPath(&cfg.Hawkbit.DownloadPath, false)
	default:
		return errors.New("unknown configuration key")
	}
	return nil
}

func identifier(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' || char == '@') {
			return false
		}
	}
	return true
}

func hawkbitComplete(cfg HawkbitConfig) bool {
	return cfg.ServerURL != "" && cfg.Tenant != "" && cfg.Token != ""
}
