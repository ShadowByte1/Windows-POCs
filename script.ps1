# Create Minimal-CLFS.ps1 from inside PowerShell
$s = @'
$ErrorActionPreference = 'Stop'

Write-Host '=== OS INFO ==='
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List

Write-Host "`n=== CLFS BINARY INFO ==="
$clfs = "$env:WINDIR\System32\drivers\clfs.sys"
if (Test-Path $clfs) {
  Get-Item $clfs | Select-Object FullName,Length,LastWriteTimeUtc
  Get-FileHash $clfs -Algorithm SHA256
} else {
  Write-Host "clfs.sys not found at $clfs"
}

Write-Host "`n=== SC QUERY clfs ==="
cmd /c 'sc query clfs' 2>&1

Write-Host "`n=== SC QC clfs ==="
cmd /c 'sc qc clfs' 2>&1

Write-Host "`n=== DRIVERQUERY (filter: clfs) ==="
cmd /c 'driverquery /v' 2>&1 | Select-String -Pattern '(?i)\bclfs(\.sys)?\b'

Write-Host "`nDone."
'@
[IO.File]::WriteAllText("$PWD\Minimal-CLFS.ps1",$s,[Text.UTF8Encoding]::new($false))
