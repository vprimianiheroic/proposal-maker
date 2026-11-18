#!/usr/bin/env bash
# Cross-compiles every agent flavour plus the server into dist/.
#
#   VERSION=1.2.0 ./scripts/build.sh
#
# Modern agent builds (Windows 10 / Server 2016 and later) use the current Go
# toolchain. Legacy builds (Windows 7 SP1, 8.1, Server 2008 R2, 2012, 2012 R2)
# need Go 1.20.x, the last release supporting those OSes. Point GO_LEGACY at
# such a toolchain, e.g.:
#   go install golang.org/dl/go1.20.14@latest && go1.20.14 download
#   GO_LEGACY=$(command -v go1.20.14) ./scripts/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
GO="${GO:-go}"
GO_LEGACY="${GO_LEGACY:-}"
OUT=dist
rm -rf "$OUT" && mkdir -p "$OUT"
export CGO_ENABLED=0

build_agent() { # toolchain arch variant
  local gobin=$1 arch=$2 variant=$3 suffix=""
  [[ -n $variant ]] && suffix="-$variant"
  local out="$OUT/rmm-agent-windows-${arch}${suffix}.exe"
  GOOS=windows GOARCH=$arch "$gobin" build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION -X main.variant=$variant" \
    -o "$out" ./cmd/rmm-agent
  echo "built $out"
}

for arch in amd64 386 arm64; do build_agent "$GO" "$arch" ""; done

if [[ -n $GO_LEGACY ]]; then
  "$GO_LEGACY" version | grep -q 'go1\.20' || { echo "GO_LEGACY must be a Go 1.20.x toolchain" >&2; exit 1; }
  for arch in amd64 386; do build_agent "$GO_LEGACY" "$arch" legacy; done
else
  echo "GO_LEGACY not set: skipping Windows 7/2008R2/2012R2 builds" >&2
fi

for target in linux/amd64 windows/amd64; do
  os=${target%/*} arch=${target#*/} ext=""
  [[ $os == windows ]] && ext=".exe"
  GOOS=$os GOARCH=$arch "$GO" build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT/rmm-server-$os-$arch$ext" ./cmd/rmm-server
  echo "built $OUT/rmm-server-$os-$arch$ext"
done

cp installer/Install-AIRMMAgent.ps1 installer/Uninstall-AIRMMAgent.ps1 installer/airmm.conf.example "$OUT/"
(cd "$OUT" && sha256sum * > SHA256SUMS)
echo "version $VERSION -> $OUT/"
