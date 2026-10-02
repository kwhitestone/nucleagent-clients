#!/bin/bash
set -euo pipefail
runner_root="$(cd "$(dirname "$0")" && pwd)"
runner_binary="${RUNNER_BINARY:-$runner_root/nucleagent-runner-darwin-arm64}"
evidence="${EVIDENCE_DIRECTORY:-$runner_root/evidence}"
mkdir -p "$evidence"
[ "$(uname -m)" = arm64 ] || { echo 'Apple Silicon is required for this native build.' >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo 'Run as your ordinary user, never sudo.' >&2; exit 1; }
sw_vers > "$evidence/platform.txt"
# Ad-hoc is not Developer ID signing or notarization. Never remove quarantine
# attributes or disable Gatekeeper as an automatic repair.
codesign --verify --verbose=2 "$runner_binary" 2> "$evidence/codesign-verify.txt"
"$runner_binary" doctor | tee "$evidence/doctor.json"
if [ "${1:-}" = --install ]; then
    for backend in codex opencode; do
        "$runner_binary" install --backend "$backend" | tee "$evidence/$backend-install.jsonl"
        "$runner_binary" verify --backend "$backend" > "$evidence/$backend-integrity.json"
    done
fi
printf '%s\n' 'Native diagnostics only; real model tasks: 0. Device registration, ACK and full task E2E are not exercised by this script.' > "$evidence/scope.txt"
