Windows isolation feasibility probes — G9-ISO, 2026-10-02

STATUS: experimental diagnostics plus fail-closed Windows task admission.
The pinned CLI still cannot initialize; P5 is blocked.
Do not connect this package to platform.Start/admission until the design gates
pass. Neither an exit-zero diagnostic nor a successful --version authorizes a
task. Stage 3 now replaces the Windows platform.Start Job-only launch with an
isolation_unavailable refusal. runBridge and executeNative also reject before
credentials, task directories, skills, or LLM proxy use. This is a refusal gate,
NOT an operational isolated task path. Non-Windows policy is unchanged.

Stage 2 historical observations (Windows 11 26200, Codex 0.149.1):
* Full task-specific restricting SID + Low IL: suspended token/job verified,
  then loader fails opening \\KnownDlls (STATUS_ACCESS_DENIED, 0xc0000022).
* SAFER constrained token followed by the new restricting SID: second token
  creation fails ERROR_INVALID_PARAMETER. No weaker-token retry is performed.
* AppContainer + privilege-restricted token + Low IL + private desktop + Job:
  Go helper and codex --version run with DETACHED_PROCESS. CREATE_NO_WINDOW
  failed KERNELBASE initialization on this host; debugger loader logs recorded
  that separate diagnostic. The AppContainer package SID supplies the file
  boundary in this candidate; TokenRestrictedSids is empty, not task-SID RT.
* Helper writes workspace/tmp, rejects runtime/control/outside/profile writes,
  sensitive/sibling canary reads and WRITE_DAC. This is a partial negative
  matrix, not proof against every path, broker, or descendant escape.
* Loopback is unreachable with both zero capabilities and internetClient.
  Broker connects successfully to the exact same test listener. No machine
  loopback exemptions, firewall changes, real credentials or inference used.
* Codex app-server exits before initialize: CODEX_HOME canonicalization denied.
  Directory metadata opens but GetFinalPathNameByHandle fails. No returned
  workspaceWrite policy, real task completion or Codex-created deliverable.

Reproduce on Windows (Go 1.26.1, from runner directory):
  go build -o windows-isolation-probe.exe ./cmd/windows-isolation-probe
  go test -v ./internal/isolation/windows
  .\acceptance\windows-isolation.ps1 -Probe <absolute-probe-exe> \
    -Codex <absolute-codex-0.149.1-exe> -Base <disposable-NTFS-directory> \
    -Evidence <diagnostic-output-directory>
The backslashes above indicate line wrapping, not PowerShell continuation.
For cross compilation: GOOS=windows GOARCH=amd64 go build ./...

Each case creates a fresh task tree and unique SID. Writable subtrees are Low
IL with modify rights; runtime is read/execute. Broker control has no task ACE.
OWNER RIGHTS prevents implicit WRITE_DAC. AppContainer's freshly created
package/profile tree is sealed read-only and deleted after Job cleanup.
Task/output trees are deliberately retained for evidence. No host/system ACL
is modified. Cleanup reports active Job process count and API errors.

Processes use CREATE_SUSPENDED, atomic PROC_THREAD_ATTRIBUTE_JOB_LIST, an
explicit stdio handle list, clean environment, CreateProcessAsUser, and token /
Job checks before ResumeThread. Limits: 8 processes, 512 MiB Job memory, 20%
aggregate CPU, kill-on-close, no breakaway, UI mask 0xde and private desktop.
Query evidence does not replace resource-limit stress or broker-crash testing.
The child independently queries token, Job membership and desktop names.

Before production reuse, remaining work includes: runtime/object read closure;
Codex integration with the now-tested task broker transport;
canonical paths; handle-pinned paths/TOCTOU protection; a dedicated launch
broker for the process-wide window-station switch; comprehensive descendant,
reparse/hardlink/ADS/registry/host-broker negative tests; cleanup fault injection;
resource-limit stress; plain-standard-user acceptance; validated sandbox
protocol and actual model E2E. macOS isolation remains separate P1 work.

The optional x64 loader diagnostic enables NtGlobalFlag loader snaps only in
the newly created suspended child. It neither changes system registry/ACLs nor
changes token, Job or filesystem policy, and is not acceptance evidence for
ordinary process lifetime behavior. Do not supply credentials to these probes.

Stage 3 — broker relay, 2026-10-02
---------------------------------
relay_windows.go uses Microsoft go-winio 0.6.2 for cancelable named-pipe I/O.
The broker creates the pipe under the task package's session namespace:
  \\.\pipe\Sessions\<session>\AppContainerNamedObjects\<SID>\<nonce>
The AppContainer opens the corresponding \\.\pipe\LOCAL\<nonce> name.
Using the same LOCAL string in both host and AppContainer names different
objects on this host, so that naive implementation returns FILE_NOT_FOUND.

Protected DACL: broker owner full control, one package SID 0x12019b,
OWNER RIGHTS read-control only, Low mandatory label. The package grant excludes
FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, WRITE_OWNER and DELETE. No Everyone or
ALL APPLICATION PACKAGES grant. Remote clients rejected by go-winio. A kernel
client PID lookup checks package SID, no network capabilities, restricted token,
Low IL and the exact task Job before serving HTTP. Even a host process with the
correct task token is rejected. Connection count 8, concurrent requests 2,
headers 16 KiB, bodies 4 MiB, read/idle/upstream deadlines, task-scoped cancellation.

HTTP is limited to POST /v1/responses and a task-scoped random 256-bit token.
No absolute URL, query, CONNECT, redirects, Origin, fetch metadata or upgrades.
Only Content-Type and broker-selected upstream Authorization are forwarded.
The immutable target is the pre-existing scoped loopback LLM proxy; that proxy
alone holds the Core key and fixes Core origin/model/budget. The disposable
native test uses a fixture at this proxy boundary; it is NOT actual Core or LLM.

StartTaskHTTPRelay is an untrusted same-AppContainer HTTP-to-pipe helper. The
native probe tests it and direct pipe HTTP in both a child and its descendant.
The descendant needs DETACHED_PROCESS too; without it the host reproduced
DLL initialization exit 0xc0000142. A real Codex+helper process session has NOT
passed because Codex fails first during CODEX_HOME canonicalization.

CODEX_HOME/HOME/USERPROFILE/TEMP/TMP/TMPDIR/APPDATA/LOCALAPPDATA and XDG cache,
config and data paths are explicit task-root paths. The created AppContainer
profile stays sealed read-only; neither parent nor descendant can write there.
This does not mean no OS profile exists: creation/deletion is broker-managed.
DOS GetFinalPathNameByHandle flags 0/8 fails with ERROR_ACCESS_DENIED; NT flags
2/10 succeeds on the same handle. -nt-home substitutes
broker-derived GLOBALROOT environment paths; pinned Codex still exits 1 before
initialize. Mere environment redirection is insufficient for this binary.

Tests: relay routing/auth/body limit/streaming, redirect rejection, host peer
rejection; native child+descendant token/Job and file probes; instance creation
and pipe ACL modification denied; Windows bridge/platform refusal before side
effects. These extend, but do not complete, the original security matrix.
No bypass, global loopback exception, system-object ACL changes, CLI binary
patch or real model request. Standard-user acceptance and P5 remain outstanding.
