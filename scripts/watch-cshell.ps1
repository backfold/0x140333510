$src = 'H:\Program Files\Nexon\SuddenAttack'
$dst = 'H:\SA_Analysis\target'
$watch = @('cshell.dll','cres.dll','ClientFX.fxd')
$deadline = (Get-Date).AddHours(2)
while ((Get-Date) -lt $deadline) {
  foreach ($f in $watch) {
    $p = Join-Path $src $f
    if (Test-Path $p) {
      try {
        Copy-Item $p (Join-Path $dst $f) -Force
        $log = "$(Get-Date -Format s) captured $f ($($(Get-Item $p).Length) bytes)"
        Add-Content 'H:\SA_Analysis\evidence\cshell_watch.log' $log
      } catch {
        Add-Content 'H:\SA_Analysis\evidence\cshell_watch.log' "$(Get-Date -Format s) copy-fail $f : $($_.Exception.Message)"
      }
    }
  }
  $have = ($watch | Where-Object { Test-Path (Join-Path $dst $_) }).Count
  if ($have -eq $watch.Count) { Add-Content 'H:\SA_Analysis\evidence\cshell_watch.log' "$(Get-Date -Format s) all captured"; break }
  Start-Sleep -Seconds 20
}
Add-Content 'H:\SA_Analysis\evidence\cshell_watch.log' "$(Get-Date -Format s) watcher exit"
