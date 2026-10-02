#!/usr/bin/env bash
set -euo pipefail
client_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
shell_source="${SHELL_SOURCE:?Set SHELL_SOURCE to the shell checkout}"
build_config="${SHELL_BUILD_CONFIG:?Set SHELL_BUILD_CONFIG to the deployment-owned JSON input file}"
runtime_source="${RUNTIME_SOURCE:-$(dirname "$shell_source")/prism-fusion}"
node --input-type=module - "$shell_source" "$runtime_source" <<'JS'
import { execFileSync } from 'node:child_process';
const [shell, runtime] = process.argv.slice(2);
const lock = JSON.parse(execFileSync('git', ['-C', shell, 'show', 'HEAD:workspace.lock.json'], { encoding: 'utf8' }));
const pin = lock.dependencies.find(item => item.name === 'prism-fusion')?.commit;
const actual = execFileSync('git', ['-C', runtime, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (!pin || pin !== actual) throw new Error('Runtime checkout does not match the shell workspace lock');
JS
build_root="$client_root/.shell-build"
mkdir -p "$build_root/nucleagent-web" "$build_root/prism-fusion"
git -C "$shell_source" archive HEAD | tar -x -C "$build_root/nucleagent-web"
git -C "$runtime_source" archive HEAD src/web/src/plugin | tar -x -C "$build_root/prism-fusion"
cd "$build_root/nucleagent-web"
npm ci --no-audit --no-fund
node "$client_root/scripts/prepare-shell.mjs" "$client_root"
node --input-type=module - "$client_root" "$build_config" <<'JS'
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const root = process.argv[2];
const input = JSON.parse(readFileSync(process.argv[3], 'utf8'));
const result = spawnSync('npm', ['run', 'build'], { stdio: 'inherit', env: { ...process.env, ...input } });
process.exit(result.status ?? 1);
JS
rm -rf "$client_root/dist/shell"
mkdir -p "$client_root/dist/shell"
cp -a dist/. "$client_root/dist/shell/"
node "$client_root/scripts/copy-runner-panel.mjs"
node --input-type=module - "$client_root" "$shell_source" "$runtime_source" "$build_config" <<'JS'
import { writeFileSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const [root, shell, runtime, inputPath] = process.argv.slice(2);
const revision = (path) => execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
writeFileSync(`${root}/dist/shell-build.json`, JSON.stringify({ shell: revision(shell), runtime: revision(runtime), inputs: JSON.parse(readFileSync(inputPath, 'utf8')) }, null, 2) + '\n');
JS
