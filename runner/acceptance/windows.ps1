param(
    [string]$Runner = "$PSScriptRoot\nucleagent-runner.exe",
    [string]$EvidenceDirectory = "$PSScriptRoot\evidence",
    [switch]$Install
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$doctorText = & $Runner doctor
if ($LASTEXITCODE -ne 0) { throw 'Runner diagnostic failed' }
$doctorText | Set-Content -Encoding UTF8 "$EvidenceDirectory\doctor.json"
& whoami.exe /groups /fo csv | Set-Content -Encoding UTF8 "$EvidenceDirectory\groups.csv"
$doctor = $doctorText | ConvertFrom-Json
if (-not $doctor.nativeUserReady) {
    throw 'Use a standard non-administrator Windows session. With UAC disabled, an administrator account may remain elevated even through Explorer or a Limited scheduled task. No backend was started.'
}
if ($Install) {
    foreach ($backend in @('codex', 'opencode')) {
        & $Runner install --backend $backend | Tee-Object -FilePath "$EvidenceDirectory\$backend-install.jsonl"
        if ($LASTEXITCODE -ne 0) { throw "$backend installation/protocol probe failed" }
        & $Runner verify --backend $backend | Set-Content -Encoding UTF8 "$EvidenceDirectory\$backend-integrity.json"
        if ($LASTEXITCODE -ne 0) { throw "$backend integrity failed" }
    }
}
@{ platform = 'Windows native'; realTasks = 0; e2e = 'NOT IMPLEMENTED: private-device bridge and Core routing required'; installRequested = [bool]$Install } | ConvertTo-Json | Set-Content -Encoding UTF8 "$EvidenceDirectory\scope.json"
Write-Output 'Native diagnostics completed. This is not task or P0 acceptance. No model task was submitted.'
