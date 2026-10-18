# launch-fast.ps1 — ngm:// URL 즉시 실행 (토큰 TTL 대응 원클릭)
#   하는 일:
#     1) passarg IP 파싱
#     2) 12000 리슨 상태/업스트림 확인 → 불일치/부재면 프록시 자동 재시작(백그라운드 분리)
#     3) 리슨 확정 대기 후 passarg IP 치환 → suddenattack.exe 실행
#   사용: powershell -File launch-fast.ps1 -NgmUrl "ngm://launch/..."
param(
  [Parameter(Mandatory=$true)][string]$NgmUrl,
  [string]$Exe = 'H:\Program Files\Nexon\SuddenAttack\suddenattack.exe',
  [string]$ProxyHost = '127.0.0.1',
  [string]$Outdir = 'H:\SA_Analysis\logs\run2',
  [string]$ProxyScript = 'H:\SA_Analysis\scripts\py\sa-proxy.js'
)
$ErrorActionPreference = 'Stop'

if ($NgmUrl -notmatch '^ngm://launch/') { Write-Error 'ngm://launch/ URL 아님'; exit 1 }
$dec = [Uri]::UnescapeDataString($NgmUrl -replace '^ngm://launch/', '')
if ($dec -notmatch "-passarg:'([^']+)'") { Write-Error 'passarg 파싱 실패'; exit 1 }
$orig = $Matches[1]; $parts = $orig -split ' '
$ip = $parts[0]; $port = if ($parts.Count -gt 1) { $parts[1] } else { '12000' }
Write-Host ("passarg 서버: {0}:{1}" -f $ip, $port)

# --- 프록시 상태 점검/정리 ---
function Get-ListenerPid($p) {
  $c = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
  if ($c) { return ($c | Select-Object -First 1).OwningProcess } return $null
}
$metaPath = Join-Path $Outdir 'meta.json'
$needRestart = $false
$lp = Get-ListenerPid $port
if (-not $lp) {
  Write-Host '프록시 다운 → 기동'
  $needRestart = $true
} else {
  try {
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    if ($meta.upstream -ne ("{0}:{1}" -f $ip, $port)) {
      Write-Host ("업스트림 불일치 (현={0} 필요={1}) → 재시작" -f $meta.upstream, "$ip`:$port")
      $needRestart = $true
    } else { Write-Host '프록시 OK (리슨+업스트림 일치)' }
  } catch { Write-Host 'meta.json 없음 → 재시작'; $needRestart = $true }
}
if ($needRestart) {
  if ($lp) { Stop-Process -Id $lp -Force -Confirm:$false; Start-Sleep -Milliseconds 600 }
  Start-Process node -WindowStyle Hidden -ArgumentList ('"{0}" --listen 127.0.0.1:{1} --upstream {2}:{1} --outdir "{3}"' -f $ProxyScript, $port, $ip, $Outdir)
  $ok = $false
  foreach ($i in 1..40) {
    Start-Sleep -Milliseconds 250
    if (Get-ListenerPid $port) { $ok = $true; break }
  }
  if (-not $ok) { Write-Error '프록시 리슨 실패 — 중단'; exit 1 }
  Start-Sleep -Milliseconds 400
  Write-Host '프록시 리슨 확정'
}

# --- 게임 실행 ---
$parts[0] = $ProxyHost
$dec = $dec.Replace($orig, ($parts -join ' ')).Replace("'", '"')
Write-Host ('실행: ' + $Exe)
Start-Process -FilePath $Exe -ArgumentList $dec
Write-Host '실행 완료 — 로비 진입 후 채팅 마커 입력(ZKTEST7391)'
