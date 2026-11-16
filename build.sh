#!/usr/bin/env bash
set -euo pipefail

package_only=0
case "${1:-}" in
    --package-only) package_only=1; shift ;;
    -h|--help)
        echo "Usage: $0 [--package-only] [go-executable]"
        echo "  --package-only  Package the existing binary and generate its SBOM offline."
        exit 0 ;;
esac
if (( $# > 1 )); then
    echo "Usage: $0 [--package-only] [go-executable]" >&2
    exit 2
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$project_dir/build" "$project_dir/output"
export CGO_ENABLED=0
export GOOS="${GOOS:-linux}"
export GOARCH="${GOARCH:-arm64}"
export GOTOOLCHAIN=local
export GOCACHE="${GOCACHE:-$project_dir/build/go-cache}"
export GOMODCACHE="${GOMODCACHE:-$project_dir/build/go-mod-cache}"

go_executable="${1:-go}"

if (( ! package_only )); then
    "$go_executable" -C "$project_dir" build -mod=readonly -trimpath \
        -gcflags=all=-l -buildvcs=false -ldflags='-s -w' -o "$project_dir/build/naos-core" ./cmd/naos-core
    echo "Built: $project_dir/build/naos-core ($GOOS/$GOARCH)"
fi

python3 "$project_dir/tools/package.py" --go "$go_executable" \
    --source "$project_dir" --binary "$project_dir/build/naos-core" \
    --output "$project_dir/output/naos-core-$GOOS-$GOARCH.tar.gz"
