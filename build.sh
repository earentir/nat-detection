#!/usr/bin/env bash
# build.sh  –  cross‑compile all nat‑detection binaries into ./bin/
set -euo pipefail

# ─── build matrix ────────────────────────────────────────────────
targets=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

# binary name → module path (relative to repo root)
declare -A bins=(
  [natcheck]="./client"
  [stun]="./server/stun"
  [whoami]="./server/whoami"
  [asnlookup]="./tools/asnlookup"
)

# ─── build metadata for ldflags ──────────────────────────────────
version=${VERSION:-$(git describe --tags --always 2>/dev/null || echo "dev")}
commit=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "none")}
date=${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}

ldflags="-s -w \
  -X 'main.version=${version}' \
  -X 'main.commit=${commit}' \
  -X 'main.date=${date}'"

echo "Building version ${version} (commit ${commit})"

# ─── clean /bin ─────────────────────────────────────────────────
rm -rf bin
mkdir -p bin

# ─── cross‑compile loop ─────────────────────────────────────────
for tgt in "${targets[@]}"; do
  IFS=/ read -r GOOS GOARCH <<<"${tgt}"
  echo "→ ${GOOS}/${GOARCH}"

  export GOOS GOARCH CGO_ENABLED=0
  suffix=""
  [[ "$GOOS" == "windows" ]] && suffix=".exe"

  for name in "${!bins[@]}"; do
    path="${bins[$name]}"
    outDir="bin/${GOOS}_${GOARCH}"
    mkdir -p "${outDir}"

    echo "   • ${name}${suffix}"
    go build -trimpath -ldflags="${ldflags}" \
      -o "${outDir}/${name}${suffix}" "${path}"
  done
done

echo "✓ all binaries are in ./bin/"
