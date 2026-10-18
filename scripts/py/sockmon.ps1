# sockmon.ps1 - sample all TCP connections of the game process family every 500ms
# Usage: powershell -File sockmon.ps1 <seconds> <outfile>
param(
  [int]$Seconds = 180,
  [string]$Outfile = 'H:\SA_Analysis\logs\run2\sockmon.log'
)
$deadline = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt $deadline) {
  $procs = @{}
  foreach ($p in (Get-Process suddenattack,eaclaunch,sacefprocess -ErrorAction SilentlyContinue)) { $procs[[int]$p.Id] = $p.ProcessName }
  if ($procs.Count -gt 0) {
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
      ($procs.ContainsKey([int]$_.OwningProcess)) -and ($_.State -ne 'Bound')
    }
    foreach ($c in $conns) {
      $line = "{0} pid={1}({2}) {3} {4}:{5} -> {6}:{7}" -f (Get-Date -Format 'HH:mm:ss.fff'), $c.OwningProcess, $procs[[int]$c.OwningProcess], $c.State, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort
      Add-Content -Path $Outfile -Value $line -Encoding UTF8
    }
  }
  Start-Sleep -Milliseconds 500
}
