param(
  [Parameter(Mandatory=$true)][string]$Probe,
  [Parameter(Mandatory=$true)][string]$Codex,
  [Parameter(Mandatory=$true)][string]$Base,
  [Parameter(Mandatory=$true)][string]$Evidence
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding
New-Item -ItemType Directory -Force $Base,$Evidence | Out-Null
$cases=@(
  @{Name='rt';Args=@()},
  @{Name='rt-loader';Args=@('-loader-trace')},
  @{Name='safer';Args=@('-safer')},
  @{Name='appcontainer';Args=@('-appcontainer')},
  @{Name='appcontainer-internet';Args=@('-appcontainer','-internet-client')},
  @{Name='codex-version';Args=@('-appcontainer','-exe',$Codex,'--','--version')},
  @{Name='codex-session';Args=@('-appcontainer','-session','-exe',$Codex)},
  @{Name='codex-session-nt';Args=@('-appcontainer','-session','-nt-home','-exe',$Codex)}
)
$summary=@()
foreach($case in $cases){
  $arguments=@('-base',$Base)+$case.Args
  $json=& $Probe @arguments
  $code=$LASTEXITCODE
  $r=$json | ConvertFrom-Json
  [IO.File]::WriteAllText((Join-Path $Evidence ($case.Name+'.json')),($json -join "`n"),(New-Object Text.UTF8Encoding($false)))
  $summary+=@{name=$case.Name;exit=$code;stage=$r.Stage;error=$r.Error;resumed=$r.Resumed;relayFixtureRequests=$r.RelayRequests;jobActiveAfterCleanup=$r.ActiveProcessesAfterCleanup;cleanupError=$r.CleanupError;profileCleanupError=$r.ProfileCleanupError}
}
$manifest=@{timestamp=[DateTime]::UtcNow.ToString('o');probeSHA256=(Get-FileHash $Probe -Algorithm SHA256).Hash;codexSHA256=(Get-FileHash $Codex -Algorithm SHA256).Hash;cases=$summary;inferenceRequests=0;productionAdmission='FAIL-CLOSED: Windows tasks unavailable until isolated CLI passes';note='Diagnostic observations only. Exit 0 is not an isolation acceptance certificate.'}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $Evidence 'matrix.json')
$manifest | ConvertTo-Json -Depth 8
