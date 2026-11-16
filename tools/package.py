#!/usr/bin/env python3
"""Package the independently built Core and its actual dependency licenses."""

import argparse
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
import tempfile


REPO = Path(__file__).resolve().parents[1]
DEPENDENCY_LICENSES = {
    "godbus-dbus": "github.com/godbus/dbus/v5",
    "go-ini": "gopkg.in/ini.v1",
}
RUNTIME_FILES = (
    ("init.d/naos-core", "etc/init.d/naos-core", 0o755),
    ("init.d/naosd", "etc/init.d/naosd", 0o755),
    ("config/device.ini.example", "etc/naos-core/device.ini", 0o600),
    ("config/naosd.yml", "etc/naosd/config.yml", 0o644),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def command(go, source, *arguments):
    # Do not copy stdout/stderr into package metadata: Go tools report local
    # absolute directories there. Only specifically selected values are saved.
    environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    result = subprocess.run([go, "-C", str(source), *arguments], capture_output=True, text=True, check=True, env=environment)
    return result.stdout.strip()


def ordinary_bytes(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), "Package input must be an ordinary file")
    return path.read_bytes()


def source_manifest(source):
    paths = {source / "go.mod", source / "go.sum"}
    for directory in ("cmd", "internal"):
        paths.update((source / directory).rglob("*.go"))
    records = [{"path": path.relative_to(source).as_posix(), "sha256": sha256(ordinary_bytes(path))}
               for path in sorted(paths, key=lambda value: value.relative_to(source).as_posix())]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return records, sha256(canonical)


def verify_linux_elf(binary, architecture):
    require(binary[:4] == b"\x7fELF" and len(binary) >= 64, "Linux Core must be an ELF executable")
    endian = {1: "<", 2: ">"}.get(binary[5])
    require(endian is not None, "Unknown ELF byte order")
    machine = struct.unpack_from(endian + "H", binary, 18)[0]
    expected = {"arm64": 183, "amd64": 62, "arm": 40, "386": 3, "riscv64": 243, "s390x": 22,
                "ppc64": 21, "ppc64le": 21, "mips": 8, "mipsle": 8, "mips64": 8, "mips64le": 8, "loong64": 258}
    require(architecture in expected and machine == expected[architecture], "ELF machine differs from Go build information")
    if binary[4] == 2:
        offset = struct.unpack_from(endian + "Q", binary, 32)[0]
        entry_size, count = struct.unpack_from(endian + "HH", binary, 54)
        minimum = 56
    else:
        require(binary[4] == 1, "Unknown ELF class")
        offset = struct.unpack_from(endian + "I", binary, 28)[0]
        entry_size, count = struct.unpack_from(endian + "HH", binary, 42)
        minimum = 32
    require(entry_size >= minimum and count > 0 and offset + count * entry_size <= len(binary), "Invalid ELF program headers")
    kinds = {struct.unpack_from(endian + "I", binary, offset + index * entry_size)[0] for index in range(count)}
    require(2 not in kinds and 3 not in kinds, "Core must be static, without a dynamic segment or interpreter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="The same Go executable used to build this binary")
    parser.add_argument("--source", type=Path, default=REPO)
    parser.add_argument("--binary", type=Path, default=REPO / "build/naos-core")
    parser.add_argument("--output", type=Path, help="Defaults to output/naos-core-<actual GOOS>-<actual GOARCH>.tar.gz")
    args = parser.parse_args()
    source, binary_path = args.source.resolve(), args.binary.resolve()
    generator_path = source / "tools/release_sbom.py"
    spec = importlib.util.spec_from_file_location("naos_core_release_sbom", generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    binary = ordinary_bytes(binary_path)
    version_text = command(args.go, source, "version", "-m", str(binary_path))
    linked = generator.parse_build_info(version_text)
    go_version = linked["go_version"]
    actual_version = command(args.go, source, "env", "GOVERSION")
    require(go_version == actual_version and re.fullmatch(r"go[0-9][A-Za-z0-9.+-]*", go_version),
            "Binary was not built with the supplied Go compiler")
    settings = linked["settings"]
    target_os, architecture = settings.get("GOOS", ""), settings.get("GOARCH", "")
    require(all(re.fullmatch(r"[a-z0-9]+", value) for value in (target_os, architecture)), "Missing Go target OS/architecture")
    require(settings.get("CGO_ENABLED") == "0", "Core must be built with CGO_ENABLED=0")
    if target_os == "linux":
        verify_linux_elf(binary, architecture)
    goroot = Path(command(args.go, source, "env", "GOROOT"))
    modules = linked["modules"]
    licenses = []
    notice_names = {path: name for name, path in DEPENDENCY_LICENSES.items()}
    for path, version in sorted(modules.items()):
        require(path in notice_names, "No release license notice mapping for an actual linked Go module")
        name = notice_names[path]
        module = json.loads(command(args.go, source, "list", "-mod=readonly", "-m", "-json", path))
        require(module.get("Path") == path and module.get("Version") == version and module.get("Dir") and not module.get("Replace"),
                "Cached module does not match the version actually linked into this binary")
        licenses.append((f"usr/share/licenses/naos-core/{name}-LICENSE",
                         ordinary_bytes(Path(module["Dir"]) / "LICENSE"), 0o644))
    records, source_hash = source_manifest(source)
    build_tags = sorted(set(settings.get("-tags", "").replace(",", " ").split()))
    metadata = {"schema_version": 1, "go_version": go_version, "goos": target_os, "goarch": architecture,
                "build_tags": build_tags, "gcflags": settings.get("-gcflags", ""),
                "cgo_enabled": 0, "binary_sha256": sha256(binary), "source_sha256": source_hash, "source_files": records,
                "modules": modules}
    members = [("usr/bin/naos-core", binary, 0o755),
               ("usr/share/licenses/naos-core/go-LICENSE", ordinary_bytes(goroot / "LICENSE"), 0o644),
               ("build-info.json", json.dumps(metadata, sort_keys=True, indent=2).encode() + b"\n", 0o644)]
    members.extend(licenses)
    members.extend((destination, ordinary_bytes(source / relative), mode)
                   for relative, destination, mode in RUNTIME_FILES)
    members.append(("sbom.spdx.json", generator.generate(metadata, {name: data for name, data, mode in members}, version_text), 0o644))
    output = args.output or REPO / "output" / f"naos-core-{target_os}-{architecture}.tar.gz"
    require(output.name == f"naos-core-{target_os}-{architecture}.tar.gz", "Archive filename must match the actual binary target")
    output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".naos-core-", suffix=".tar.gz", dir=output.parent)
    try:
        with os.fdopen(handle, "wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", compresslevel=9, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                    for name, data, mode in members:
                        entry = tarfile.TarInfo(name)
                        entry.uid, entry.gid, entry.uname, entry.gname = 0, 0, "", ""
                        entry.mode, entry.mtime, entry.size = mode, 0, len(data)
                        archive.addfile(entry, io.BytesIO(data))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Packaged: {output} ({target_os}/{architecture}, {go_version}, SHA256 {sha256(output.read_bytes())})")


if __name__ == "__main__":
    main()
