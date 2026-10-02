#!/bin/bash
set -euo pipefail
runner_root="$(cd "$(dirname "$0")" && pwd)"
runner_binary="${RUNNER_BINARY:-$runner_root/nucleagent-runner-darwin-arm64}"
[ "$(uname -s)" = Darwin ] || { echo 'Ad-hoc verification must run on macOS.' >&2; exit 1; }
codesign --force --sign - "$runner_binary"
codesign --verify --strict --verbose=2 "$runner_binary"
echo 'Ad-hoc signed locally. Not notarized; no Apple Developer ID identity is asserted.'
