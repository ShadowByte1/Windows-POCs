<# 
  Check-CLFS.ps1
  - Shows OS info
  - Reports CLFS service/driver status and clfs.sys hash/version
  - Checks for \GLOBAL??\clfscntrl (\\.\clfscntrl) via QueryDosDevice
  - Tries to open \\.\clfscntrl safely
#>

[CmdletBinding()]
param()

function Assert-Admin {
    $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell (Run as administrator)."
    }
}

function Get-OSInfo {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            Caption     = $os.Caption
            Version     = $os.Version
            BuildNumber = $os.BuildNumber
            InstallDate = $os.InstallDate
        }
    } catch {
        Write-Warning "Unable to query OS info: $($_.Exception.Message)"
    }
}

function Get-CLFSBinaryInfo {
    $driverPath = Join-Path $env:WINDIR 'System32\drivers\clfs.sys'
    if (Test-Path $driverPath) {
        try {
            $fi = Get-Item $driverPath
            $sha256 = Get-FileHash $driverPath -Algorithm SHA256
            [pscustomobject]@{
                Path          = $fi.FullName
                Length        = $fi.Length
                Version       = $fi.VersionInfo.FileVersion
                SHA256        = $sha256.Hash
                LastWriteTime = $fi.LastWriteTimeUtc
            }
        } catch {
            Write-Warning "Failed to read CLFS binary info: $($_.Exception.Message)"
        }
    } else {
        [pscustomobject]@{
            Path    = $driverPath
            Present = $false
        }
    }
}

function Get-CLFSServiceInfo {
    Write-Output "=== SC QUERY clfs ==="
    try {
        cmd /c 'sc query clfs' 2>&1
    } catch {
        Write-Warning "sc query failed: $($_.Exception.Message)"
    }

    Write-Output "`n=== SC QC clfs ==="
    try {
        cmd /c 'sc qc clfs' 2>&1
    } catch {
        Write-Warning "sc qc failed: $($_.Exception.Message)"
    }
}

function Get-CLFSDriverEntry {
    Write-Output "=== DRIVERQUERY (filter: clfs) ==="
    try {
        cmd /c 'driverquery /v' 2>&1 | Select-String -Pattern '(?i)\bclfs(\.sys)?\b'
    } catch {
        Write-Warning "driverquery failed: $($_.Exception.Message)"
    }
}

# --- Add-Type for kernel32 P/Invokes (QueryDosDevice + CreateFile) ---
$kernel32 = @"
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

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

try { Add-Type -TypeDefinition $kernel32 -ErrorAction Stop }
catch { Write-Error "Add-Type failed: $($_.Exception.Message)"; exit 1 }

function Test-DosDeviceLink {
    param([Parameter(Mandatory=$true)][string]$Name)
    $sb = New-Object System.Text.StringBuilder 8192
    $len = [K32]::QueryDosDevice($Name, $sb, $sb.Capacity)
    if ($len -eq 0) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [pscustomobject]@{
            Name    = $Name
            Exists  = $false
            Targets = @()
            Error   = $err
        }
    } else {
        $targets = $sb.ToString().TrimEnd([char]0) -split [char]0
        [pscustomobject]@{
            Name    = $Name
            Exists  = $true
            Targets = $targets
            Error   = 0
        }
    }
}

function Test-OpenDevicePath {
    param([Parameter(Mandatory=$true)][string]$Path)
    $access = [K32]::GENERIC_READ -bor [K32]::GENERIC_WRITE
    $share  = [K32]::FILE_SHARE_READ -bor [K32]::FILE_SHARE_WRITE -bor [K32]::FILE_SHARE_DELETE
    $h = [K32]::CreateFile($Path, $access, $share, [IntPtr]::Zero, [K32]::OPEN_EXISTING, [K32]::FILE_ATTRIBUTE_NORMAL, [IntPtr]::Zero)
    if ($h -eq [K32]::INVALID_HANDLE_VALUE) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [pscustomobject]@{ Path=$Path; Opened=$false; LastError=$err }
    } else {
        [void][K32]::CloseHandle($h)
        [pscustomobject]@{ Path=$Path; Opened=$true; LastError=0 }
    }
}

# ---------------- MAIN ----------------
try { Assert-Admin } catch { Write-Error $_.Exception.Message; exit 1 }

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
