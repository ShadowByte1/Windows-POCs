# Check-CLFS.ps1
# Queries CLFS service/driver status and tests whether a user-mode device link exists.

[CmdletBinding()]
param()

function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    throw "Run this script from an elevated PowerShell (Run as administrator)."
  }
}

function Get-OSInfo {
  $os = Get-CimInstance Win32_OperatingSystem
  [pscustomobject]@{
    Caption     = $os.Caption
    Version     = $os.Version
    BuildNumber = $os.BuildNumber
    InstallDate = $os.InstallDate
  }
}

function Get-CLFSServiceInfo {
  Write-Output "=== SC QUERY CLFS ==="
  cmd /c 'sc query clfs' 2>&1 | Out-String

  Write-Output "`n=== SC QC CLFS ==="
  cmd /c 'sc qc clfs' 2>&1 | Out-String
}

function Get-CLFSDriverEntry {
  Write-Output "=== DRIVERQUERY (CLFS) ==="
  # driverquery returns modules list; filter for clfs.sys or CLFS
  cmd /c 'driverquery /v' 2>&1 | Select-String -Pattern '(?i)\bclfs\b|\bclfs\.sys\b' | Out-String
}

# P/Invoke helpers for QueryDosDevice + CreateFileW
$kernel32 = @"
using System;
using System.Runtime.InteropServices;

public static class K32 {
    public const uint GENERIC_READ  = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ  = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

Add-Type -TypeDefinition $kernel32 -ErrorAction Stop

function Test-DosDeviceLink {
  param([Parameter(Mandatory=$true)][string]$Name)
  $sb = New-Object System.Text.StringBuilder 8192
  $len = [K32]::QueryDosDevice($Name, $sb, $sb.Capacity)
  if ($len -eq 0) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    return [pscustomobject]@{
      Name    = $Name
      Exists  = $false
      Targets = @()
      Error   = $err
    }
  } else {
    # QueryDosDevice may return multiple nul-separated paths
    $targets = $sb.ToString().TrimEnd([char]0) -split [char]0
    return [pscustomobject]@{
      Name    = $Name
      Exists  = $true
      Targets = $targets
      Error   = 0
    }
  }
}

function Test-OpenDevicePath {
  param([Parameter(Mandatory=$true)][string]$Path)
  $GENERIC = [K32]::GENERIC_READ -bor [K32]::GENERIC_WRITE
  $SHARE   = [K32]::FILE_SHARE_READ -bor [K32]::FILE_SHARE_WRITE -bor [K32]::FILE_SHARE_DELETE
  $h = [K32]::CreateFile($Path, $GENERIC, $SHARE, [IntPtr]::Zero,
                         [K32]::OPEN_EXISTING, [K32]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
  if ($h -eq [IntPtr]::MinusOne) {
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    return [pscustomobject]@{ Path=$Path; Opened=$false; LastError=$err }
  } else {
    [void][K32]::CloseHandle($h)
    return [pscustomobject]@{ Path=$Path; Opened=$true; LastError=0 }
  }
}

function Get-CLFSBinaryInfo {
  $driverPath = Join-Path $env:WINDIR 'System32\drivers\clfs.sys'
  if (Test-Path $driverPath) {
    $fi = Get-Item $driverPath
    $sha256 = Get-FileHash $driverPath -Algorithm SHA256
    [pscustomobject]@{
      Path    = $fi.FullName
      Length  = $fi.Length
      Version = (Get-Item $fi.FullName).VersionInfo.FileVersion
      SHA256  = $sha256.Hash
      LastWriteTime = $fi.LastWriteTimeUtc
    }
  } else {
    [pscustomobject]@{
      Path    = $driverPath
      Present = $false
    }
  }
}

# ---- main ----
try {
  Assert-Admin
} catch {
  Write-Error $_.Exception.Message
  exit 1
}

Write-Host "=== OS INFO ===" -ForegroundColor Cyan
Get-OSInfo | Format-List

Write-Host "`n=== CLFS BINARY INFO ===" -ForegroundColor Cyan
Get-CLFSBinaryInfo | Format-List

Write-Host "`n" -NoNewline; Get-CLFSServiceInfo
Write-Host "`n" -NoNewline; Get-CLFSDriverEntry

Write-Host "`n=== QueryDosDevice('clfscntrl') ===" -ForegroundColor Cyan
$dos = Test-DosDeviceLink -Name 'clfscntrl'
$dos | Format-List

Write-Host "`n=== Attempt CreateFile('\\\\.\\clfscntrl') ===" -ForegroundColor Cyan
$open = Test-OpenDevicePath -Path '\\.\clfscntrl'
$open | Format-List

Write-Host "`n=== Summary ===" -ForegroundColor Yellow
if (-not $dos.Exists -and -not $open.Opened) {
  Write-Host "No user-mode device link 'clfscntrl' found; CLFS likely exposes no \\.\ control device on this build."
} elseif ($dos.Exists -and $open.Opened) {
  Write-Host "Device link exists and is openable."
} else {
  Write-Host "Mixed results—inspect details above."
}
