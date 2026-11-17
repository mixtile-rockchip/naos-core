# NAOS Core

**English** | [简体中文](README.zh-CN.md)

NAOS device management service and command-line interface for Linux.

## Features

- Local CLI, Unix socket API, and optional HTTP API.
- Container queries and control through `naosd`.
- Signed RAUC system and bootloader updates, hawkBit registration and update scheduling.
- OEM identity, hostname and mDNS management, and hardware watchdog support.
- Device reboot and factory reset.

## Binary releases

Download the Linux ARM64 package from [Releases](https://github.com/mixtile-rockchip/naos-core/releases/latest).

The archive includes:

| Path | Contents |
|---|---|
| `usr/bin/naos-core` | Static Core executable |
| `etc/naos-core/device.ini` | Core configuration template |
| `etc/naosd/config.yml` | Container runtime configuration |
| `etc/init.d/` | OpenRC service scripts |
| `usr/share/licenses/naos-core/` | Go and dependency licenses |
| `build-info.json` | Target, toolchain, dependency and file checksums |
| `sbom.spdx.json` | SPDX software bill of materials |

## Source layout

| Directory | Contents |
|---|---|
| `cmd/naos-core/` | CLI and service entry points |
| `internal/` | Device management, container control, OTA and API implementations |
| `config/` | Configuration templates |
| `init.d/` | OpenRC service scripts |
| `tools/` | Release packaging and SBOM generation |

## Build

Requires Go 1.23 or later, Bash, and Python 3.

```sh
./build.sh
```

To select a Go executable:

```sh
./build.sh /path/to/go
```

The default target is Linux ARM64. Outputs are `build/naos-core` and `output/naos-core-linux-arm64.tar.gz`.

## Configuration

Use [config/device.ini.example](config/device.ini.example) as `/etc/naos-core/device.ini`. Commands accept `--config PATH` to select another file.

The default Unix socket is `/run/naos/core.sock`; the optional HTTP API listens on `127.0.0.1:8890`. Restart Core after manually editing the configuration. Successful `hawkbit register` applies registration settings to the running service.

To start a configured application at boot, set `[container] enabled=true` and `manifest` to its manifest under `/userdata/` or `/var/lib/naos/containers/<id>/manifest.yml`.

## Commands

```sh
naos-core --help
sudo naos-core serve
sudo naos-core oem
sudo naos-core containers
sudo naos-core containers start myapp
sudo naos-core hawkbit status
sudo naos-core hawkbit check
```

Register a device using the organization's Gateway Token:

```sh
sudo naos-core hawkbit register \
  --server https://ota.example.com \
  --tenant DEFAULT \
  --token GATEWAY_TOKEN
```
