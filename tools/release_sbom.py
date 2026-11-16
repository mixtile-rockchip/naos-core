#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Describe an independently built Core release using SPDX 2.3, offline.

The binary's embedded ``go version -m`` records decide which Go dependencies
are present. A go.sum file or the complete module-cache graph is never used.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
from urllib.parse import quote


MODULE_LICENSE_FILES = {
    "github.com/godbus/dbus/v5": "usr/share/licenses/naos-core/godbus-dbus-LICENSE",
    "gopkg.in/ini.v1": "usr/share/licenses/naos-core/go-ini-LICENSE",
}
# Exact reviewed notice bytes. A changed notice becomes an extracted license
# with its real text, rather than inheriting an unchecked SPDX identifier.
KNOWN_LICENSE_TEXTS = {
    "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad": "BSD-3-Clause",
    "e4646a82a976369d7ae8f6ed5c11d35dc0af18433a8ccc24c85b459ad8b95128": "BSD-2-Clause",
    "f6918bd93ffe07f4b2c61b8287c32cb3122e08aed0be50f1c7d0eddc87877a8f": "Apache-2.0",
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _path(value):
    if not isinstance(value, str) or not value or value.startswith("/") or "\0" in value or ".." in value.split("/"):
        raise ValueError("Release members must have safe relative paths")
    result = str(PurePosixPath(value))
    if result == ".":
        raise ValueError("A release file cannot be the archive root")
    return result


def parse_build_info(text):
    """Parse actual linked modules and build settings, rejecting replacements."""
    lines = text.splitlines()
    if not lines or ": " not in lines[0]:
        raise ValueError("Missing binary Go build information")
    version = lines[0].rsplit(": ", 1)[1]
    if not re.fullmatch(r"go[0-9][A-Za-z0-9.+-]*", version):
        raise ValueError("Invalid embedded Go version")
    modules, settings, module_checksums = {}, {}, {}
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if fields[0] == "=>":
            raise ValueError("Replaced Go modules require explicit release provenance")
        if fields[0] == "dep":
            if len(fields) < 3 or not fields[1] or not fields[2] or fields[1] in modules:
                raise ValueError("Invalid or duplicate embedded Go module")
            modules[fields[1]] = fields[2]
            if len(fields) > 3 and fields[3]:
                module_checksums[fields[1]] = fields[3]
        elif len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            settings[key] = value
    return {"go_version": version, "modules": modules, "settings": settings,
            "module_checksums": module_checksums}


def generate(build_info, members, go_version_text, *, module_license_files=None, epoch=0):
    """Return standard SPDX 2.3 JSON bytes for ordinary archive members.

    ``members`` maps the final relative filename to its exact bytes and omits
    sbom.spdx.json itself. It contains the binary, runtime files, notices and
    build-info.json.
    """
    payloads = {}
    for name, data in members.items():
        path = _path(name)
        if path == "sbom.spdx.json":
            continue
        if path in payloads or not isinstance(data, bytes):
            raise ValueError("Duplicate release member or non-byte payload")
        payloads[path] = data
    binary_path = "usr/bin/naos-core"
    if binary_path not in payloads or "build-info.json" not in payloads:
        raise ValueError("Core release requires its binary and build-info.json")
    if json.loads(payloads["build-info.json"]) != build_info:
        raise ValueError("Supplied build metadata differs from distributed build-info.json")
    linked = parse_build_info(go_version_text)
    for key in ("go_version", "modules"):
        if build_info.get(key) != linked[key]:
            raise ValueError("Distributed build metadata differs from embedded " + key)
    settings = linked["settings"]
    if (settings.get("CGO_ENABLED") != "0" or build_info.get("cgo_enabled") != 0
            or any(build_info.get(field) != settings.get(setting) for field, setting in (("goos", "GOOS"), ("goarch", "GOARCH")))):
        raise ValueError("Release target/static build settings differ from the binary")
    binary_checksum = _sha256(payloads[binary_path])
    if build_info.get("binary_sha256") != binary_checksum:
        raise ValueError("Release binary differs from build-info.json")
    source_checksum = build_info.get("source_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_checksum):
        raise ValueError("Missing independent source-content digest")
    license_files = dict(MODULE_LICENSE_FILES if module_license_files is None else module_license_files)
    extracted = {}

    def notice(path):
        path = _path(path)
        if path not in payloads:
            raise ValueError("Missing actual dependency license notice: " + path)
        data = payloads[path]
        checksum = _sha256(data)
        expression = KNOWN_LICENSE_TEXTS.get(checksum)
        if expression is None:
            expression = "LicenseRef-Notice-" + checksum
            extracted[expression] = {"licenseId": expression, "name": "Distributed dependency notice",
                                     "extractedText": data.decode("utf-8")}
        return expression, path

    def identifier(kind, value):
        return "SPDXRef-" + kind + "-" + _sha256(_canonical(value))

    checksums = {name: {"SHA256": _sha256(data), "SHA1": hashlib.sha1(data).hexdigest()}
                 for name, data in sorted(payloads.items())}
    files = [{"SPDXID": identifier("File", name), "fileName": name,
              "checksums": [{"algorithm": algorithm, "checksumValue": value} for algorithm, value in sorted(checksums[name].items())],
              "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION"}
             for name in sorted(payloads)]
    file_ids = {entry["fileName"]: entry["SPDXID"] for entry in files}
    package_verification = hashlib.sha1("".join(sorted(record["SHA1"] for record in checksums.values())).encode()).hexdigest()
    source_version = "sha256-" + source_checksum
    app = {"SPDXID": "SPDXRef-Core", "name": "naos-core", "versionInfo": source_version,
           "packageFileName": binary_path, "downloadLocation": "NOASSERTION", "supplier": "Organization: NAOS",
           "filesAnalyzed": True, "packageVerificationCode": {"packageVerificationCodeValue": package_verification},
           "checksums": [{"algorithm": "SHA256", "checksumValue": binary_checksum}],
           "hasFiles": sorted(file_ids.values()), "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
           "licenseInfoFromFiles": ["NOASSERTION"], "copyrightText": "NOASSERTION",
           "sourceInfo": "Independent source-content SHA256: " + source_checksum + "; target: " + build_info["goos"] + "/" + build_info["goarch"],
           "comment": "Application license was not declared. Dependency notices do not establish an application license. Static dependencies are limited to the Go runtime and embedded linked-module records.",
           "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                             "referenceLocator": "pkg:generic/naos/naos-core@" + source_version + "?arch=" + quote(build_info["goarch"], safe="") + "&os=" + quote(build_info["goos"], safe="")}]}
    packages = [app]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": app["SPDXID"]}]
    relationships.extend({"spdxElementId": app["SPDXID"], "relationshipType": "CONTAINS", "relatedSpdxElement": item["SPDXID"]} for item in files)

    def dependency(package, license_path):
        packages.append(package)
        relationships.append({"spdxElementId": app["SPDXID"], "relationshipType": "STATIC_LINK", "relatedSpdxElement": package["SPDXID"]})
        relationships.append({"spdxElementId": package["SPDXID"], "relationshipType": "OTHER", "relatedSpdxElement": file_ids[license_path],
                              "comment": "The release distributes this exact dependency license notice; it does not distribute separate dependency source files."})

    expression, path = notice("usr/share/licenses/naos-core/go-LICENSE")
    dependency({"SPDXID": "SPDXRef-GoRuntime", "name": "Go standard library and runtime", "versionInfo": linked["go_version"].removeprefix("go"),
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": expression,
                "copyrightText": "NOASSERTION", "comment": "Runtime and standard library statically linked into Core; this is not a shipped Go compiler."}, path)
    for name, version in sorted(linked["modules"].items()):
        if name not in license_files:
            raise ValueError("No release notice mapping for actual linked module: " + name)
        expression, path = notice(license_files[name])
        dependency({"SPDXID": identifier("GoModule", [name, version]), "name": name, "versionInfo": version,
                    "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": expression,
                    "copyrightText": "NOASSERTION", "sourceInfo": "Embedded Go module checksum (Go directory hash, not an archive SHA256): " + linked["module_checksums"].get(name, "not supplied"),
                    "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                      "referenceLocator": "pkg:golang/" + quote(name, safe="/") + "@" + quote(version, safe="")}]}, path)
    document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "naos-core-" + build_info["goos"] + "-" + build_info["goarch"],
                "creationInfo": {"creators": ["Organization: NAOS", "Tool: naos-core-release-sbom"],
                                 "created": datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                "comment": "Actual independent Core release. File hashes cover archive payloads except this SBOM itself. Only binary-reported Go dependencies are asserted; unused modules and test dependencies are not inferred.",
                "packages": sorted(packages, key=lambda item: item["SPDXID"]), "files": files,
                "relationships": sorted(relationships, key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"]))}
    if extracted:
        document["hasExtractedLicensingInfos"] = [extracted[key] for key in sorted(extracted)]
    # Namespace identifies the complete semantic document, including notices,
    # license decisions and tool metadata, without a recursive self-reference.
    document["documentNamespace"] = "https://spdx.org/spdxdocs/naos-core-" + _sha256(_canonical(document))
    return json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2).encode() + b"\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="Existing Core release archive")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--go", default="go", help="Go executable, used only to read embedded binary metadata")
    parser.add_argument("--epoch", type=int, default=0)
    args = parser.parse_args()
    members = {}
    with tarfile.open(args.package, "r:gz") as archive:
        for entry in archive:
            name = _path(entry.name)
            if entry.isdir():
                continue
            if not entry.isfile() or name in members:
                raise ValueError("Release archive contains a non-ordinary or duplicate member")
            members[name] = archive.extractfile(entry).read()
    metadata = json.loads(members["build-info.json"])
    with tempfile.NamedTemporaryFile(prefix="naos-core-buildinfo-") as binary:
        binary.write(members["usr/bin/naos-core"])
        binary.flush()
        env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
        result = subprocess.run([args.go, "version", "-m", binary.name], check=True, capture_output=True, text=True, env=env)
    payload = generate(metadata, members, result.stdout, epoch=args.epoch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print("Core SBOM: " + str(args.output) + " (SHA256 " + _sha256(payload) + ")")


if __name__ == "__main__":
    main()
