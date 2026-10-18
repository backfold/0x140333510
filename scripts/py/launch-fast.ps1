# launch-fast.ps1 - one-shot launcher for TTL-critical ngm:// captures
#   1) parse passarg IP:port
#   2) verify proxy on port (listen + upstream match via meta.json), restart if needed
#   3) wait for LISTEN, substitute passarg IP with proxy host, Start-Process the game
# Usage: powershell -File launch-fast.ps1 -NgmUrl "ngm://launch/..."
param(
  [Parameter(Mandatory=$true)][string]$NgmUrl,
  [string]$Exe = 'H:\Program Files\Nexon\SuddenAttack\suddenattack.exe',
  [string]$ProxyHost = '127.0.0.1',
  [string]$Outdir = 'H:\SA_Analysis\logs\run2',
  [string]$ProxyScript = 'H:\SA_Analysis\scripts\py\sa-proxy.js',
  [switch]$NoSubstitute   # control test: leave passarg untouched, skip proxy mgmt
)
$ErrorActionPreference = 'Stop'

if ($NgmUrl -notmatch '^ngm://launch/') { Write-Error 'not an ngm://launch/ URL'; exit 1 }
$enc = $NgmUrl -replace '^ngm://launch/', ''
$dec = [Uri]::UnescapeDataString($enc)
if ($dec -notmatch "-passarg:'([^']+)'") { Write-Error 'passarg parse failed'; exit 1 }
$orig = $Matches[1]; $parts = $orig -split ' '
$ip = $parts[0]; $port = if ($parts.Count -gt 1) { $parts[1] } else { '12000' }
Write-Host ("passarg server: {0}:{1}" -f $ip, $port)

# control mode: leave passarg untouched, no proxy management
if ($NoSubstitute) {
  $decCtrl = $dec.Replace("'", '"')
  Write-Host ('CONTROL LAUNCH (no substitution): ' + $Exe)
  Start-Process -FilePath $Exe -ArgumentList $decCtrl
  Write-Host 'launched unmodified'
  exit 0
}

function Get-ListenerPid($p) {
  $c = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
  if ($c) { return ($c | Select-Object -First 1).OwningProcess } return $null
}
$metaPath = Join-Path $Outdir 'meta.json'
$needRestart = $false
$lp = Get-ListenerPid $port
if (-not $lp) {
  Write-Host 'proxy down -> starting'
  $needRestart = $true
} else {
  try {
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $want = "{0}:{1}" -f $ip, $port
    if ($meta.upstream -ne $want) {
      Write-Host ("upstream mismatch (have={0} want={1}) -> restart" -f $meta.upstream, $want)
      $needRestart = $true
    } else { Write-Host 'proxy OK (listening, upstream matches)' }
  } catch { Write-Host 'meta.json unreadable -> restart'; $needRestart = $true }
}
if ($needRestart) {
  if ($lp) { Stop-Process -Id $lp -Force -Confirm:$false; Start-Sleep -Milliseconds 600 }
  $argline = '"{0}" --listen 127.0.0.1:{1} --upstream {2}:{1} --outdir "{3}"' -f $ProxyScript, $port, $ip, $Outdir
  Start-Process node -WindowStyle Hidden -ArgumentList $argline
  $ok = $false
  foreach ($i in 1..40) {
    Start-Sleep -Milliseconds 250
    if (Get-ListenerPid $port) { $ok = $true; break }
  }
  if (-not $ok) { Write-Error 'proxy failed to listen - aborting'; exit 1 }
  Start-Sleep -Milliseconds 400
  Write-Host 'proxy listening confirmed'
}

$parts[0] = $ProxyHost
$dec = $dec.Replace($orig, ($parts -join ' ')).Replace("'", '"')
Write-Host ('launching: ' + $Exe)
Start-Process -FilePath $Exe -ArgumentList $dec
Write-Host 'launched - enter lobby, then type chat marker ZKTEST7391'
