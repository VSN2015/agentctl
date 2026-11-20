#!/usr/bin/env bash
# Builds static release archives for darwin/linux x amd64/arm64 into dist/.
set -euo pipefail

if [ $# -ne 1 ] || ! [[ $1 =~ ^[0-9A-Za-z.+-]+$ ]]; then
  echo "usage: scripts/build.sh <version>   (for example 0.1.0)" >&2
  exit 2
fi
version=$1
cd "$(dirname "$0")/.."

go mod verify
rm -rf dist
mkdir dist

for os in darwin linux; do
  for arch in amd64 arm64; do
    name="agentctl_${version}_${os}_${arch}"
    mkdir -p "dist/$name"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -mod=readonly -trimpath \
      -ldflags "-s -w -X github.com/VSN2015/agentctl/internal/cli.Version=$version" \
      -o "dist/$name/agentctl" ./cmd/agentctl
    cp LICENSE README.md "dist/$name/"
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  done
done

# Bare file names in the checksum file, so `shasum -c` works from the download directory.
cd dist
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 ./*.tar.gz | sed 's#\./##' > SHA256SUMS
else
  sha256sum ./*.tar.gz | sed 's#\./##' > SHA256SUMS
fi
