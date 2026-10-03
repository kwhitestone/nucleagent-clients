NucleAgent native runner operation manual

The runner binds a private PC to an authenticated Core user. It accepts one
Codex task at a time, streams output, uploads generated files, saves a terminal
result, and waits for a matching Core ACK before releasing the slot. A worker
exit or a successful network write is not a confirmed completion.

Prerequisites
- Windows 11 amd64 in a standard, non-elevated user session, or macOS 15 arm64.
- Core containing the private-device/ACK implementation and its pinned Shared
  revision. Ordinary server executor credentials cannot authenticate this runner.
- HTTPS Core origin, trusted system certificates, an explicit provider/model,
  and permission to run the selected task with the current user's access.
- Native binaries do not use WSL as a PC target. Doctor always refuses Linux.
- Signed runtime catalog: Codex 0.149.1 and OpenCode 1.18.23. OpenCode currently
  supports installation/probing only; the executable run command advertises Codex.

Build
  cd runner
  GOWORK=off go test -race ./...
  GOWORK=off go vet ./...
  cd ..
  GOWORK=off bash scripts/build-runner.sh

Go pins Shared through its canonical repository with a fixed pseudo-version.
Private repository access must be configured using the caller's authorized Git
identity. No credentials or local worktree paths are required in go.mod. Local
optional go.work files are ignored and are not release verification inputs.
The script creates Windows/macOS sidecars and dist/runner/SHA256SUMS. Tauri
packaging additionally requires the native platform toolchain and dist/shell.
Build local shell assets with `npm ci` and `npm run shell:build`, setting
SHELL_SOURCE to the source checkout, RUNTIME_SOURCE to its locked Prism checkout,
and SHELL_BUILD_CONFIG to deployment-owned JSON containing the required Vite
origins. Build inputs and commit IDs are recorded in dist/shell-build.json.
Deployment values are not product defaults. The shell script exports committed
source and verifies its runtime pin before applying the client-only overlay.

First use
1. Run `nucleagent-runner doctor`. Stop if nativeUserReady is false. There is no
   privilege override. Do not disable UAC, change accounts or launch a service
   to bypass the check. A Limited scheduled task with UAC disabled is not proof
   of a standard-user session.
2. Run `nucleagent-runner bind --core-origin https://core.example.com` using the
   actual authorized Core origin, or use Bind in the packaged local panel.
   Enter the displayed binding ID and short code in the signed-in TaskSetup
   device section. The native process exchanges its proof only after confirmation.
3. Wait for bound, then copy the device ID. `device-status` displays only public
   binding metadata. The credential/private key live in DPAPI on Windows or
   Keychain on macOS; local records use 0600 or restrictive native ACLs.
4. Run `nucleagent-runner run --backend codex --enable --consent-native-access`,
   or enable Codex admission in the local panel. Missing runtimes download from
   the signed, fixed catalog, verify archive and complete file closure, then
   pass a real empty-session protocol probe before registration/admission.
5. In TaskSetup select the PC, Codex, provider/model and skills. A deep link uses
   `/tasks?skillIds=12&device=<device-id>&backend=codex`. The values are suggestions;
   Core revalidates owner, current socket, admission, backend and capacity.
6. Save requested files directly under workspace/artifacts. At most ten regular
   files, each up to 100 MiB, are uploaded using the per-run artifact capability.
   Core stores canonical file references with the terminal message. View them
   in the task and its scoped deliverables panel; Hub also links to the results
   library. Local-panel task links use the configured trusted shell origin.

Use one absolute --data-dir consistently if overriding the default. Defaults
are LOCALAPPDATA/NucleAgent/runner on Windows and the user's configuration
folder/NucleAgent/runner on macOS. The application lock prevents concurrent
installation, vault mutation or duplicate runners. Task homes and workspaces
are private, but their paths do not constitute an OS security sandbox.

Windows Codex sandbox (per-task configuration)
The broker precreates <task>/home/codex/config.toml, which is the worker's actual
CODEX_HOME. It never edits the user's global Codex configuration:

  approval_policy = "never"
  sandbox_mode = "workspace-write"
  [windows]
  sandbox = "unelevated"

Codex 0.149.1 resolves workspace-write to readOnly when its Windows sandbox
implementation is disabled. A writable workspace, external Job/token, TEMP/TMP,
or omitting the thread/start sandbox field does not enable that implementation.
The fixed-version source is config/src/config_toml.rs at rust-v0.149.1; see also
https://learn.chatgpt.com/docs/windows/windows-sandbox . The native unelevated
mode uses restricted tokens and ACLs, with weaker network controls than elevated.

The Windows production launcher requires task-local canonical configuration,
verified private directory ACLs, a random private desktop, and atomic Job
membership before resuming a worker. Missing prerequisites fail closed. The Job
caps the process tree and is killed on broker exit; normal cleanup waits for all
descendants before closing the desktop. The adapter refuses a non-workspaceWrite
thread/start response before turn/start. The outer app-server remains a trusted
same-user process: private desktop means a separate launch desktop, not a claim
that its user identity cannot open other desktops. Task ACLs provide privacy
from other users, not protection from the same user. Write-scope enforcement
belongs to Codex's sandboxed tool children. No AppContainer isolation is claimed.

The AppContainer/B-prime probes remain under internal/isolation/windows and the
separate windows-isolation-probe command. Production never imports this package.
Do not invoke a diagnostic helper as an execution backend. Windows OpenCode task
execution remains unsupported. The signed Codex Windows catalog declares adapter
version 2 and windowsSandbox=unelevated; old declarations cannot register tasks.

Credential-free composition verification (native Windows test binary):
  Set G9_WINDOWS_CODEX_FIXTURE to the hash-verified 0.149.1 codex.exe, then run
  the adapter tests with -test.run=TestWindowsCodexSandbox -test.v. This checks
  effective policy, actual workspace write, and denial of an outside canary
  through the production launcher without model inference. This test must pass
  on the deployment host before spending a real-task budget. Cross-build success
  alone is insufficient. Native acceptance status belongs in the deployment report.

Acknowledgements and recovery
- Acceptance: the generation (conversation/step/nonce and original request ID)
  is fsynced before a2a_response 200 and before worker launch.
- Completion: terminal results are persisted locally before transmission. Until
  Core returns accepted/duplicate with the exact request, step and nonce, the
  event is awaiting-ack and capacity remains occupied. Reconnect retries the
  same stored result, not the task. Core commits message/state/artifacts/receipt
  atomically before ACK. A lost ACK is deduplicated even after a later turn.
- The panel's resultStatus is the worker's report. Core's receipt is authoritative;
  a concurrent cancellation can make Core's final state cancelled. Open the task
  to inspect its persisted outcome.
- Windows Job Objects terminate workers/descendants when the runner is killed.
  After restart, a ledger entry without a result becomes executor_interrupted.
  It is sent and acknowledged without rerunning the same nonce. A deliberate
  retry must create a new step/nonce.
- Graceful Stop closes the control pipe, cancels the active worker and waits for
  cleanup. After an offline stop the next Run replays the saved terminal result.
- Cleanup/integrity failures remain a durable admission fence across reconnects.
  Investigate and repair the installation/process state; do not delete a live
  ledger or its nonce fences to force admission.
- macOS hard-crash cleanup cannot yet prove the old process group is gone. A
  pending active ledger entry fails closed on restart; automatic crash recovery
  on macOS remains unaccepted pending native process-cleanup validation.
- The ledger retains up to 10,000 generations and refuses further admission when
  full. Text output is bounded; Core visibly truncates text at its DB limit.
  Task directories are retained locally; review storage use and remove only
  confirmed inactive task directories, never ledger entries or credentials.
- Core restart during an unfinished artifact upload can invalidate the ephemeral
  upload grant. The task reports failure; receipt replay for committed results
  remains supported.

Control and credentials
`renew` rotates the device credential; the old token/socket is fenced. Run
renews near expiry by draining an idle connection and reconnecting. Ledgers are
scoped to the instance identity so rebinding never overwrites old nonce fences. `revoke` requires confirmed remote
revocation before deleting the local credential. Stop the running bridge first.
The main/remote webview cannot call runner IPC; only the packaged local panel
has the permission, and each command checks the caller label and local origin.
Core credentials never enter CLI environment or storage upload requests. The
CLI receives a per-task loopback proxy token. Raw CLI diagnostics are discarded.

Offline checks versus acceptance
The optional G9_CODEX_PROTOCOL_FIXTURE tests exercise a real verified Linux CLI
against a fake loopback Responses service, without inference or paid tasks.
They are protocol evidence only. Linux Rust tests and Windows/macOS cross builds
are not native UI, vault, process-tree, installer or real task acceptance.

For the <=2 Windows real-task budget, use task one for kill/restart injection:
verify Core has not completed it, restart, receive the interrupted generation's
ACK, then deliberately retry as a fresh nonce for task two. Verify streaming,
ACK, persisted final message and downloadable artifact on the second attempt.
Never spend an extra task to hide a failed attempt. Keep macOS native acceptance
explicitly pending when no real machine is available.

Release limitations
The embedded catalog uses an engineering signing key. Hash/closure verification
is not upstream publisher signing. macOS cross builds use an ad-hoc signature;
Developer ID signing, notarization, real-machine smoke and crash recovery need a
native release environment. The Windows standard-user E2E must be evidenced
separately; this manual does not certify that an installation has passed it.

Private-runner skill delivery contract

Core sends each private task a short-lived absolute HTTPS URL that returns ZIP
bytes directly, together with the selected skill ID, slug, version and SHA256.
It resolves this URL only for a bound private device; shared server executors
retain their authenticated S2S download-resolution contract. Resolution failure,
changed skill identity, HTTP, missing host, userinfo or fragment fails dispatch
before credentials or execution are issued. Never log signed URLs or forward
the shared executor credential to a PC.

The runner verifies the original ZIP checksum before extraction. Packages may
contain SKILL.md at the root or use exactly one wrapper directory named after
the selected slug. Only that verified prefix is removed; unexpected mixed roots,
traversal, symlinks, case collisions and excessive sizes remain rejected. Run
the archive tests and the optional Windows package fixture before paid E2E. The
fixture accepts a binding over stdin and must not persist the signed URL.

Artifact directory and completion checks

Create workspace/artifacts with an inheritable ACL beneath the protected private
workspace. Do not apply PrivateDirectory to that child: its protected user-only
DACL blocks Codex's restricted sandbox SID even when workspace itself is writable.
The broker must still be able to read the resulting file for upload. The native
sandbox fixture tests the precreated nested directory, broker readback, and an
unchanged outside canary; root-workspace writes alone are insufficient evidence.

On Core, private artifact persistence locks both Conversation and Step. A GORM
query containing Clauses must use a reusable Session before querying different
models; otherwise the Conversation table and predicates leak into the Step query.
Preserve FOR UPDATE and the existing transaction. Test repeated completion,
checksum conflict, receipt fencing, and the locking branch, since plain SQLite
queries alone do not exercise this statement-reuse failure.

Acceptance requires upload, Core artifact completion HTTP 200, persisted artifact
projection, terminal receipt/ACK, and downloadable bytes matching the local hash.
Storage PUT 200 or registration 201 alone is insufficient.
