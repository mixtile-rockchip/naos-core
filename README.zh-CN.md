# NAOS Core

[English](README.md) | **简体中文**

NAOS 设备管理服务与命令行工具。

## 功能

- 本地 CLI、Unix socket API 和可选 HTTP API。
- 通过 `naosd` 查询和控制容器。
- RAUC 签名系统包和 bootloader 包升级、hawkBit 注册与升级调度。
- OEM 身份读取、主机名和 mDNS 管理、硬件看门狗。
- 设备重启与恢复出厂设置。

## 二进制发布

从 [Releases](https://github.com/mixtile-rockchip/naos-core/releases/latest) 下载 Linux ARM64 发布包。

归档包含：

| 路径 | 内容 |
|---|---|
| `usr/bin/naos-core` | 静态链接的 Core 程序 |
| `etc/naos-core/device.ini` | Core 配置模板 |
| `etc/naosd/config.yml` | 容器运行时配置 |
| `etc/init.d/` | OpenRC 服务脚本 |
| `usr/share/licenses/naos-core/` | Go 和依赖许可证 |
| `build-info.json` | 目标、工具链、依赖与文件校验信息 |
| `sbom.spdx.json` | SPDX 软件物料清单 |

## 源码目录

| 目录 | 内容 |
|---|---|
| `cmd/naos-core/` | CLI 和常驻服务入口 |
| `internal/` | 设备管理、容器控制、OTA 和 API 实现 |
| `config/` | 配置模板 |
| `init.d/` | OpenRC 服务脚本 |
| `tools/` | 发布包和 SBOM 生成工具 |

## 构建

需要 Go 1.23 或更新版本、Bash 和 Python 3。

```sh
./build.sh
```

指定 Go 程序路径：

```sh
./build.sh /path/to/go
```

默认构建 Linux ARM64，输出为 `build/naos-core` 和 `output/naos-core-linux-arm64.tar.gz`。

## 配置

以 [config/device.ini.example](config/device.ini.example) 为模板配置 `/etc/naos-core/device.ini`。命令可使用 `--config PATH` 指定其他配置文件。

默认 Unix socket 为 `/run/naos/core.sock`，可选 HTTP API 监听 `127.0.0.1:8890`。手动修改配置后重启 Core；`hawkbit register` 成功后会向运行中的服务应用注册配置。

需要开机启动业务时，在 `[container]` 中设置 `enabled=true`，并将 `manifest` 指向 `/userdata/` 下的业务清单或 `/var/lib/naos/containers/<id>/manifest.yml`。

## 命令

```sh
naos-core --help
sudo naos-core serve
sudo naos-core oem
sudo naos-core containers
sudo naos-core containers start myapp
sudo naos-core hawkbit status
sudo naos-core hawkbit check
```

使用组织的 Gateway Token 注册设备：

```sh
sudo naos-core hawkbit register \
  --server https://ota.example.com \
  --tenant DEFAULT \
  --token GATEWAY_TOKEN
```
