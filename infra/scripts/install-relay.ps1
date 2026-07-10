#Requires -RunAsAdministrator
<#
  install-relay.ps1 — one-command Gotham mixnet relay installer for Windows.

  Downloads the checksum-verified relay .exe, generates an identity key, and
  registers a Scheduled Task that launches the relay IN THE BACKGROUND AT EVERY
  BOOT (as SYSTEM, before login, no window) with auto-restart on failure — so
  after the PC is shut down and turned back on, the relay comes back on its own.
  Opens the Windows Firewall for the UDP port.

  Run in an ELEVATED PowerShell (no token needed, enrollment is open):
    irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex

  Env vars (all optional; same as the Linux/macOS installers):
    GOTHAM_ENROLL_TOKEN  Only if the authority runs in closed/token mode.
                         Enrollment is OPEN by default - you do NOT need one.
    GOTHAM_AUTHORITY_URL default http://144.24.205.188:8443
    GOTHAM_TIER          entry|mix|exit (default mix)
    GOTHAM_PORT          default 443
    GOTHAM_ADVERTISE_IP  optional; if unset the relay auto-maps its port and
                         detects its public IP via UPnP-IGD (home routers).
#>
$ErrorActionPreference = "Stop"

$Repo    = "0x9Angel/gotham-relay"
$Token   = $env:GOTHAM_ENROLL_TOKEN
$AuthUrl = if ($env:GOTHAM_AUTHORITY_URL) { $env:GOTHAM_AUTHORITY_URL } else { "http://144.24.205.188:8443" }
$Tier    = if ($env:GOTHAM_TIER) { $env:GOTHAM_TIER } else { "mix" }
$Port    = if ($env:GOTHAM_PORT) { $env:GOTHAM_PORT } else { "443" }

if (@("entry", "mix", "exit") -notcontains $Tier) { throw "GOTHAM_TIER must be entry|mix|exit (got '$Tier')" }

$Dir = Join-Path $env:ProgramData "Gotham"
$Bin = Join-Path $Dir "gotham-relay.exe"
$Key = Join-Path $Dir "relay.key"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Write-Host "[1/5] Downloading + verifying binary..."
$Asset = "gotham-relay-windows-x86_64.exe"
$Base  = "https://github.com/$Repo/releases/latest/download"
Invoke-WebRequest -Uri "$Base/$Asset"        -OutFile $Bin
Invoke-WebRequest -Uri "$Base/$Asset.sha256" -OutFile "$Bin.sha256"
$expected = ((Get-Content "$Bin.sha256") -split '\s+')[0].ToLower()
$actual   = (Get-FileHash $Bin -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { Remove-Item $Bin -Force; throw "Checksum verification FAILED - refusing to install." }

Write-Host "[2/5] Generating relay identity (if absent)..."
if (-not (Test-Path $Key)) { & $Bin keygen --key-file $Key | Out-Null }
$PubKey = (& $Bin pubkey --key-file $Key)

Write-Host "[3/5] Building launch command..."
$binArgs = @(
    "run", "--key-file", $Key,
    "--listen-host", "0.0.0.0", "--listen-port", $Port,
    "--authority-url", $AuthUrl, "--tier", $Tier, "--heartbeat-secs", "60"
)
if ($env:GOTHAM_ADVERTISE_IP) { $binArgs += @("--advertise-addr", "$($env:GOTHAM_ADVERTISE_IP):$Port") }
$AdvMsg = if ($env:GOTHAM_ADVERTISE_IP) { "$($env:GOTHAM_ADVERTISE_IP):$Port (manual)" } else { "auto (UPnP-IGD)" }

# Token (only in closed/token mode) via a MACHINE env var so it is not visible
# in the task's command line. Open enrollment needs none.
if ($Token) { [Environment]::SetEnvironmentVariable("GOTHAM_ENROLL_TOKEN", $Token, "Machine") }

Write-Host "[4/5] Registering boot Scheduled Task (SYSTEM, background, auto-restart)..."
$action    = New-ScheduledTaskAction -Execute $Bin -Argument ($binArgs -join " ")
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
Unregister-ScheduledTask -TaskName "GothamRelay" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "GothamRelay" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Gotham mixnet relay - auto-starts in the background at boot" | Out-Null

Write-Host "[5/5] Firewall + start now..."
New-NetFirewallRule -DisplayName "Gotham QUIC relay (UDP $Port)" -Direction Inbound `
    -Protocol UDP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
Start-ScheduledTask -TaskName "GothamRelay"

Write-Host ""
Write-Host "============================================================"
Write-Host " Gotham relay installed - starts automatically at every boot,"
Write-Host " in the background (Scheduled Task: GothamRelay)."
Write-Host " Public key : $PubKey"
Write-Host " Advertised : $AdvMsg   (tier: $Tier, port $Port/udp)"
Write-Host " Authority  : $AuthUrl"
Write-Host " Status     : Get-ScheduledTask GothamRelay | Get-ScheduledTaskInfo"
Write-Host " Stop/Start : Stop-ScheduledTask GothamRelay  /  Start-ScheduledTask GothamRelay"
Write-Host " Remove     : Unregister-ScheduledTask -TaskName GothamRelay -Confirm:`$false"
Write-Host "============================================================"
