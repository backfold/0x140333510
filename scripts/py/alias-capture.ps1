# alias-capture.ps1 - network-layer interception with ZERO modification of the launch URL
#   Adds the real game-server IP as a local /32 alias so the OS delivers the client's
#   connection to our local proxy (which forwards to the sibling real server).
#   The game is then launched 100% vanilla (user clicks 게임시작; ngm:// flow untouched).
#
#   Setup:    powershell -File alias-capture.ps1 -TargetIp 175.207.21.12 -UpstreamIp 175.207.21.11
#   Teardown: powershell -File alias-capture.ps1 -Teardown
param(
  [string]$TargetIp,
  [string]$UpstreamIp,
  [string]$Outdir = 'H:\SA_Analysis\logs\run2',
  [string]$ProxyScript = 'H:\SA_Analysis\scripts\py\sa-proxy.js',
  [int]$Port = 12000,
  [switch]$Teardown
)
$ErrorActionPreference = 'Stop'
$fwName = 'sa-proxy-12000'

function Get-DefaultIf() {
  $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
  return $r.InterfaceAlias
}

if ($Teardown) {
  Get-NetIPAddress -IPAddress $TargetIp -ErrorAction SilentlyContinue | ForEach-Object { netsh interface ipv4 delete address $_.InterfaceAlias $TargetIp | Out-Null }
  Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  $l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  if ($l) { Stop-Process -Id ($l | Select-Object -First 1).OwningProcess -Force -Confirm:$false }
  Write-Host "torn down (alias $TargetIp, fw rule, proxy)"
  exit 0
}

if (-not $TargetIp -or -not $UpstreamIp) { Write-Error 'need -TargetIp and -UpstreamIp (use the two farm IPs, e.g. .12 and .11)'; exit 1 }

# 1) alias the target IP on the default-route interface
$if = Get-DefaultIf
Write-Host ("default-route interface: {0}" -f $if)
$existing = Get-NetIPAddress -IPAddress $TargetIp -ErrorAction SilentlyContinue
if (-not $existing) {
  netsh interface ipv4 add address $if $TargetIp 255.255.255.255
  Start-Sleep -Milliseconds 500
  if (-not (Get-NetIPAddress -IPAddress $TargetIp -ErrorAction SilentlyContinue)) { Write-Error 'alias add failed'; exit 1 }
  Write-Host ("alias added: {0}/32 on {1}" -f $TargetIp, $if)
} else { Write-Host 'alias already present' }

# 2) firewall inbound allow for the proxy port
if (-not (Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $fwName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
  Write-Host 'firewall rule added (inbound TCP 12000)'
}

# 3) (re)start the proxy bound to the aliased IP
$l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($l) { Stop-Process -Id ($l | Select-Object -First 1).OwningProcess -Force -Confirm:$false; Start-Sleep -Milliseconds 600 }
$argline = '"{0}" --listen {1}:{2} --upstream {3}:{2} --outdir "{4}"' -f $ProxyScript, $TargetIp, $Port, $UpstreamIp, $Outdir
Start-Process node -WindowStyle Hidden -ArgumentList $argline
$ok = $false
foreach ($i in 1..40) {
  Start-Sleep -Milliseconds 250
  $l = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  if ($l) { $ok = $true; break }
}
if (-not $ok) { Write-Error 'proxy failed to listen on alias'; exit 1 }
Start-Sleep -Milliseconds 400
Write-Host ("proxy listening on {0}:{1} -> {2}:{1}" -f $TargetIp, $Port, $UpstreamIp)
Write-Host 'READY - now launch the game NORMALLY (click 게임시작 in the browser, vanilla). Capture is automatic.'
