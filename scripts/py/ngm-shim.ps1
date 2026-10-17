# ngm-shim.ps1 — ngm:// 프로토콜 가로채기 시먼.
# HKCU\Software\Classes\ngm 로 등록하면 HKLM 의 진짜 핸들러
# (C:\ProgramData\Nexon\NGM\NGM64.exe "%1") 대신 호출되어,
# -passarg 첫 토큰(서버 IP)만 127.0.0.1 로 바꿔 진짜 핸들러에 넘긴다.
# 토큰/나머지 인자는 그대로 → 정상 발급 흐름 유지.
#
# 안전장치: H:\SA_Analysis\logs\ngm-shim-off 파일이 있으면 치환 없이 통과.
param(
  [string]$NgmUrl = '',
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$RealHandler = 'C:\ProgramData\Nexon\NGM\NGM64.exe'
$ProxyHost = '127.0.0.1'
$LogFile = 'H:\SA_Analysis\logs\ngm-shim.log'

function Write-Log([string]$m) {
  try { Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) } catch {}
}

try {
  if (-not $NgmUrl -and $args.Count -gt 0) { $NgmUrl = [string]$args[0] }
  if (-not $NgmUrl) { Write-Log '빈 URL'; exit 1 }
  $preview = $NgmUrl.Substring(0, [Math]::Min(90, $NgmUrl.Length))

  if (Test-Path 'H:\SA_Analysis\logs\ngm-shim-off') {
    Write-Log ("PASS-THROUGH (shim-off): " + $preview)
    Start-Process -FilePath $RealHandler -ArgumentList ('"{0}"' -f $NgmUrl)
    exit 0
  }

  # URL 은 퍼센트 인코딩 상태로 전달됨: -passarg%3A'175.207.21.11%2012000...
  # IP 자체(숫자/점)는 인코딩되지 않으므로 %20 직전 첫 토큰을 치환.
  if ($NgmUrl -match "passarg%3A'([^%']+)%20") {
    $ipOld = $Matches[1]
    $NgmUrl = $NgmUrl.Replace(("passarg%3A'{0}%20" -f $ipOld), ("passarg%3A'{0}%20" -f $ProxyHost))
    Write-Log ("REWRITE passarg IP {0} -> {1} | {2}..." -f $ipOld, $ProxyHost, $preview)
  } else {
    Write-Log ("NO passarg 패턴 (통과) | " + $preview)
  }

  if ($DryRun) { Write-Log 'DRY-RUN (실행 안 함)'; exit 0 }
  Start-Process -FilePath $RealHandler -ArgumentList ('"{0}"' -f $NgmUrl)
  Write-Log 'NGM64 호출 완료'
} catch {
  Write-Log ("ERROR: " + $_.Exception.Message)
  exit 1
}
