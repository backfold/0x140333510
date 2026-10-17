param([string]$Session = 'H:\SA_Analysis\evidence\session1.jsonl', [string]$Out = 'H:\SA_Analysis\evidence\session1_digest.txt')
$lines = Get-Content $Session
$sb = New-Object System.Text.StringBuilder
foreach ($l in $lines) {
  $o = $l | ConvertFrom-Json
  $r = $null
  try { $r = $o.result | ConvertFrom-Json } catch {}
  $ev = if ($r) { $r.evidence_id } else { '' }
  [void]$sb.AppendLine("=== $($o.tool) $(($o.args | ConvertTo-Json -Compress)) ok=$($o.ok) ev=$ev")
  if ($o.ok -and $r) {
    $rr = $r.raw_result
    if ($rr) {
      $txt = $rr | ConvertTo-Json -Depth 5 -Compress
      if ($txt.Length -gt 3000) { $txt = $txt.Substring(0,3000) + '...[cut]' }
      [void]$sb.AppendLine($txt)
    } else { [void]$sb.AppendLine('(no raw_result)') }
  } elseif (-not $o.ok) { [void]$sb.AppendLine("ERROR: $($o.result)") }
  [void]$sb.AppendLine('')
}
$sb.ToString() | Out-File $Out -Encoding utf8
Get-Content $Out
