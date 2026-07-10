# diagnose-relay.ps1 — why won't my Gotham relay enroll?
#
# Runs the INSTALLED relay in the foreground for ~20s, captures its output, and
# prints a plain-language verdict. The Windows installer runs the relay as a
# background Scheduled Task whose output is not visible — this exposes it.
#
# Paste-safe one-liner (run in an ELEVATED PowerShell — Run as Administrator):
#   irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/diagnose-relay.ps1 | iex

$ErrorActionPreference = "Continue"

# iex-loaded scripts can't enforce #Requires, so check admin at runtime.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "Run this in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Yellow; return }

$dir = Join-Path $env:ProgramData "Gotham"
$bin = Join-Path $dir "gotham-relay.exe"
$key = Join-Path $dir "relay.key"
$out = Join-Path $dir "diagnose.out"
$err = Join-Path $dir "diagnose.err"
if (-not (Test-Path $bin)) { Write-Host "Relay not installed ($bin is missing). Run the installer first." -ForegroundColor Yellow; return }

$port = if ($env:GOTHAM_PORT) { $env:GOTHAM_PORT } else { "443" }
$auth = if ($env:GOTHAM_AUTHORITY_URL) { $env:GOTHAM_AUTHORITY_URL } else { "http://144.24.205.188:8443" }
$tier = if ($env:GOTHAM_TIER) { $env:GOTHAM_TIER } else { "mix" }

Write-Host "Stopping the background task, then running the relay ~20s to capture its output..."
Stop-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 1

$relayArgs = @(
  "run", "--key-file", $key,
  "--listen-host", "0.0.0.0", "--listen-port", $port,
  "--authority-url", $auth, "--tier", $tier, "--heartbeat-secs", "60"
)
if ($env:GOTHAM_ADVERTISE_IP) { $relayArgs += @("--advertise-addr", "$($env:GOTHAM_ADVERTISE_IP):$port") }

Remove-Item $out, $err -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $bin -ArgumentList $relayArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds 20
if (-not $p.HasExited) { $p.Kill(); $exit = "(still running after 20s — stopped it)" }
else { $exit = "(the relay EXITED on its own with code $($p.ExitCode) — it crashed)" }

$text = ((Get-Content $out -Raw -ErrorAction SilentlyContinue) + "`n" +
         (Get-Content $err -Raw -ErrorAction SilentlyContinue)).Trim()

Write-Host ""
Write-Host "===== RELAY OUTPUT =====" -ForegroundColor Cyan
if ($text) { Write-Host $text } else { Write-Host "(no output captured)" }
Write-Host "$exit"
Write-Host "===== VERDICT =====" -ForegroundColor Cyan
if ($text -match "enrolled|directory updated|announced") {
  Write-Host "[OK] The relay reached the authority and ENROLLED. If the background task still failed, the problem is the task setup, not the relay — reinstall." -ForegroundColor Green
}
elseif ($text -match "UPnP|IGD|external IP|advertise|CGNAT|public") {
  Write-Host "[FIX] UPnP / advertise-address failure — your router isn't mapping the port (or you're behind CGNAT)." -ForegroundColor Yellow
  Write-Host "      Find your public IP (https://api.ipify.org), forward UDP $port on your router to this PC, then reinstall with:"
  Write-Host "      `$env:GOTHAM_ADVERTISE_IP='<your.public.ip>'; irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex"
}
elseif ($text -match "bind|in use|permission|AddrInUse|10048|os error 10013|os error 10048") {
  Write-Host "[FIX] Cannot bind UDP $port (in use or blocked). Reinstall on another port:" -ForegroundColor Yellow
  Write-Host "      `$env:GOTHAM_PORT='9101'; irm https://raw.githubusercontent.com/0x9Angel/gotham-relay/main/infra/scripts/install-relay.ps1 | iex"
}
else {
  Write-Host "[?] Could not auto-classify. Copy the RELAY OUTPUT above and send it to the operator." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Restarting the background task..."
Start-ScheduledTask -TaskName GothamRelay -ErrorAction SilentlyContinue | Out-Null
