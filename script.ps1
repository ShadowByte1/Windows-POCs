# === ONE-PASTE CLFS CHECK ===
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$ErrorActionPreference='Stop'

Write-Host '=== OS INFO ===' -ForegroundColor Cyan
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List

Write-Host "`n=== CLFS BINARY INFO ===" -ForegroundColor Cyan
$clfs = "$env:WINDIR\System32\drivers\clfs.sys"
if (Test-Path $clfs) {
  Get-Item $clfs | Select-Object FullName,Length,LastWriteTimeUtc
  Get-FileHash $clfs -Algorithm SHA256
} else { Write-Host "clfs.sys not found at $clfs" }

Write-Host "`n=== SC QUERY clfs ===" -ForegroundColor Cyan
cmd /c 'sc query clfs' 2>&1

Write-Host "`n=== SC QC clfs ===" -ForegroundColor Cyan
cmd /c 'sc qc clfs' 2>&1

Write-Host "`n=== DRIVERQUERY (filter: clfs) ===" -ForegroundColor Cyan
cmd /c 'driverquery /v' 2>&1 | Select-String -Pattern '(?i)\bclfs(\.sys)?\b'

# --- Add-Type for QueryDosDevice / CreateFile (ASCII only) ---
$src = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class K32 {
  public const uint GENERIC_READ  = 0x80000000;
  public const uint GENERIC_WRITE = 0x40000000;
  public const uint FILE_SHARE_READ  = 0x00000001;
  public const uint FILE_SHARE_WRITE = 0x00000002;
  public const uint FILE_SHARE_DELETE = 0x00000004;
  public const uint OPEN_EXISTING = 3;
  public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
  public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFile(
      string lpFileName, uint dwDesiredAccess, uint dwShareMode,
      IntPtr lpSecurityAttributes, uint dwCreationDisposition,
      uint dwFlagsAndAttributes, IntPtr hTemplateFile);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);
}
"@
Add-Type -TypeDefinition $src -ErrorAction Stop

Write-Host "`n=== QueryDosDevice('clfscntrl') ===" -ForegroundColor Cyan
$sb = New-Object System.Text.StringBuilder 8192
$len = [K32]::QueryDosDevice('clfscntrl', $sb, $sb.Capacity)
if ($len -eq 0) {
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Host "Exists: False   Error: $err"
} else {
  ($sb.ToString().TrimEnd([char]0) -split [char]0) | ForEach-Object { "Target: $_" }
}

Write-Host "`n=== Attempt CreateFile('\\\\.\\clfscntrl') ===" -ForegroundColor Cyan
$acc = [K32]::GENERIC_READ -bor [K32]::GENERIC_WRITE
$shr = [K32]::FILE_SHARE_READ -bor [K32]::FILE_SHARE_WRITE -bor [K32]::FILE_SHARE_DELETE
$h = [K32]::CreateFile('\\.\clfscntrl', $acc, $shr, [IntPtr]::Zero, [K32]::OPEN_EXISTING, [K32]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
if ($h -eq [K32]::INVALID_HANDLE_VALUE) {
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Host "Opened: False   LastError: $err"
} else {
  [void][K32]::CloseHandle($h)
  Write-Host 'Opened: True   LastError: 0'
}

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
if ($len -eq 0 -and ($h -eq [K32]::INVALID_HANDLE_VALUE)) {
  Write-Host 'No user-mode device link clfscntrl found; CLFS likely exposes no \\.\ control device on this build.'
} elseif ($len -ne 0 -and ($h -ne [K32]::INVALID_HANDLE_VALUE)) {
  Write-Host 'Device link exists and is openable.'
} else {
  Write-Host 'Mixed results - check details above.'
}
