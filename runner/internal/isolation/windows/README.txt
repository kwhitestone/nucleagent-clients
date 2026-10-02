Windows isolation feasibility probes — G9-ISO, 2026-10-02

STATUS: experimental diagnostics, NOT a production isolation implementation.
Do not connect this package to platform.Start/admission until the design gates
pass. Neither an exit-zero diagnostic nor a successful --version authorizes a
task. Existing platform/adapter code is unchanged by this milestone.

Native observations (Windows 11 26200, Codex 0.149.1):
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
compatible per-task broker transport without global loopback exemptions;
canonical paths; handle-pinned paths/TOCTOU protection; a dedicated launch
broker for the process-wide window-station switch; comprehensive descendant,
reparse/hardlink/ADS/registry/host-broker negative tests; cleanup fault injection;
resource-limit stress; plain-standard-user acceptance; validated sandbox
protocol and actual model E2E. macOS isolation remains separate P1 work.

The optional x64 loader diagnostic enables NtGlobalFlag loader snaps only in
the newly created suspended child. It neither changes system registry/ACLs nor
changes token, Job or filesystem policy, and is not acceptance evidence for
ordinary process lifetime behavior. Do not supply credentials to these probes.
