#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$root/desktop/src-tauri/binaries" "$root/dist/runner"
cd "$root/runner"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o "$root/desktop/src-tauri/binaries/nucleagent-runner-x86_64-pc-windows-msvc.exe" ./cmd/nucleagent-runner
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o "$root/desktop/src-tauri/binaries/nucleagent-runner-aarch64-apple-darwin" ./cmd/nucleagent-runner
cp "$root/desktop/src-tauri/binaries/nucleagent-runner-x86_64-pc-windows-msvc.exe" "$root/dist/runner/nucleagent-runner.exe"
cp "$root/desktop/src-tauri/binaries/nucleagent-runner-aarch64-apple-darwin" "$root/dist/runner/nucleagent-runner-darwin-arm64"
cd "$root/dist/runner"
sha256sum nucleagent-runner.exe nucleagent-runner-darwin-arm64 > SHA256SUMS
