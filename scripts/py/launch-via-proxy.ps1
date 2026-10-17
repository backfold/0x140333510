# launch-via-proxy.ps1 — ngm:// 실행 URL을 받아 -passarg 의 서버 IP를
# 로컬 프록시 주소로 바꿔 suddenattack.exe 를 실행한다.
#
# 사용법:
#   1) sa_proxy.py 를 먼저 띄운다 (python sa_proxy.py --listen 127.0.0.1:12000 --upstream <실서버IP>:12000)
#   2) 이 스크립트 실행:
#      powershell -File launch-via-proxy.ps1 -NgmUrl "ngm://launch/..."
#      (인자 생략 시 클립보드에서 ngm:// URL 을 읽는다)
#
# 주의:
#   - ngm 토큰은 1회성/짧은 수명 — 새 실행 URL 을 그때그때 사용한다.
#   - 이 스크립트는 파일에 토큰을 저장하지 않는다 (메모리에서 치환 후 전달).
#   - ngm 인자가 exe 커맨드라인으로 동일하게 전달된다고 가정 [추정].
#     클라이언트가 접속을 시작하지 않으면 콘솔/프록시 로그로 확인할 것.
param(
  [string]$NgmUrl = '',
  [string]$Exe = 'H:\Program Files\Nexon\SuddenAttack\suddenattack.exe',
  [string]$ProxyHost = '127.0.0.1',
  [switch]$DryRun
)

if (-not $NgmUrl) {
  $NgmUrl = (Get-Clipboard -Raw)
  $NgmUrl = $NgmUrl.Trim()
}
if ($NgmUrl -notmatch '^ngm://launch/') {
  Write-Error 'ngm://launch/ URL 이 아님 (인자 또는 클립보드 확인)'
  exit 1
}

# ngm://launch/ 뒤의 퍼센트 인코딩 디코딩 → "-mode:launch -game:'94227' -passarg:'IP PORT ...' ..."
$enc = $NgmUrl -replace '^ngm://launch/', ''
$dec = [Uri]::UnescapeDataString($enc)

# -passarg:'...' 첫 토큰(IP)을 프록시 주소로 교체
if ($dec -match "-passarg:'([^']+)'") {
  $orig = $Matches[1]
  $parts = $orig -split ' '
  Write-Host ("원본 passarg : " + $orig)
  $parts[0] = $ProxyHost
  $new = $parts -join ' '
  $dec = $dec.Replace($orig, $new)
  Write-Host ("치환 passarg : " + $new)
} else {
  Write-Warning "-passarg 파싱 실패 — 원본 그대로 실행"
}

# 작은따옴표 → 큰따옴표 (Windows CreateProcess 관례)
$dec = $dec.Replace("'", '"')

Write-Host ("실행: " + $Exe + " " + ($dec -replace '(token:")[^"]+', '$1<REDACTED>'))
if ($DryRun) { Write-Host '(DryRun — 실제 실행 안 함)'; exit 0 }

Start-Process -FilePath $Exe -ArgumentList $dec
