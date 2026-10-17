param(
    [string]$Root = 'H:\Program Files\Nexon\SuddenAttack',
    [string]$Out  = 'H:\SA_Analysis\evidence\inventory.csv',
    [switch]$IncludeGamePkgs
)
$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null

$rows = New-Object System.Collections.Generic.List[object]
$files = Get-ChildItem $Root -Recurse -File
if (-not $IncludeGamePkgs) {
    $files = $files | Where-Object { $_.DirectoryName -notmatch '\\game$' }
}
foreach ($f in $files) {
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    $vi   = $f.VersionInfo
    $magic = ''
    $fs = [System.IO.File]::OpenRead($f.FullName)
    try {
        $buf = New-Object byte[] 4
        $n = $fs.Read($buf, 0, 4)
        if ($n -ge 2 -and $buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) { $magic = 'MZ' }
        elseif ($n -ge 4) { $magic = ('{0:X2} {1:X2} {2:X2} {3:X2}' -f $buf[0],$buf[1],$buf[2],$buf[3]) }
    } finally { $fs.Close() }

    $type = switch -Regex ($f.Extension.ToLower()) {
        '^\.(exe|dll|sys|acm|scr|ocx|cpl|efi|drv)$' { if ($magic -eq 'MZ') { 'PE' } else { 'DATA' } ; break }
        '^\.(dat|cfg|log|bak|gli|json|txt|cur|bmp|ico|sa[ed]|tp1|bin|dat)$' { 'DATA' ; break }
        default { 'DATA' }
    }
    if ($f.Extension -ieq '.pkg') { $type = 'PKG' }
    if ($f.Extension -ieq '.rez') { $type = 'REZ' }
    if ($f.Extension -ieq '.mex') { $type = 'MEX' }
    if ($f.Extension -ieq '.snd') { $type = 'SND' }
    if ($f.Extension -ieq '.aes') { $type = 'DATA' }

    $rows.Add([PSCustomObject]@{
        Path        = $f.FullName.Substring($Root.Length + 1)
        Size        = $f.Length
        SHA256      = $hash
        Type        = $type
        ProductName = $vi.ProductName
        FileVersion = $vi.FileVersion
        Description = $vi.FileDescription
        Company     = $vi.CompanyName
        LastWrite   = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    })
}
$rows | Export-Csv -Path $Out -NoTypeInformation -Encoding UTF8
"Wrote $($rows.Count) rows to $Out"
