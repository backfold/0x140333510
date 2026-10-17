$map = @{
  'FUN_1402644b8_mainCRTStartup.c'      = '0x1402644b8'
  'FUN_14007acf0_WinMain.c'              = '0x14007acf0'
  'FUN_140078f60_client_globals_init.c' = '0x140078f60'
  'FUN_14007a2f0_engine_init.c'          = '0x14007a2f0'
  'FUN_1400bef00_cshell_loader.c' = '0x1400bef4a'
  'FUN_140131010_model_load.c' = '0x140131444'
}
$dir = 'H:\SA_Analysis\decompiled'
New-Item -ItemType Directory -Force $dir | Out-Null
$sessions = 'H:\SA_Analysis\evidence\session4.jsonl','H:\SA_Analysis\evidence\session5.jsonl','H:\SA_Analysis\evidence\session6.jsonl','H:\SA_Analysis\evidence\session8.jsonl'
$records = @()
foreach ($s in $sessions) {
  foreach ($l in Get-Content $s) {
    $o = $l | ConvertFrom-Json
    if ($o.tool -ne 'procedure_pseudo_code') { continue }
    try { $r = $o.result | ConvertFrom-Json } catch { continue }
    if ($r.raw_result -and $r.raw_result.value) { $records += [PSCustomObject]@{ addr = $o.args.procedure; ev = $r.evidence_id; code = $r.raw_result.value } }
  }
}
foreach ($kv in $map.GetEnumerator()) {
  $rec = $records | Where-Object { $_.addr -eq $kv.Value } | Select-Object -First 1
  if ($rec) {
    $hdr = "// Function: $($kv.Value)`n// REA evidence_id: $($rec.ev)`n// Source: suddenattack.exe (sha256 1a2343a24dae074dd9dba63f65cd637a8a5a7384fcd6b4f2840016b78e37e741)`n"
    ($hdr + $rec.code) | Out-File (Join-Path $dir $kv.Key) -Encoding utf8
    "wrote $($kv.Key) ($($rec.code.Length) chars)"
  } else { "MISSING $($kv.Value)" }
}
