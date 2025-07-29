[CmdletBinding()]
Param();

Set-StrictMode -Version Latest

<# We couldn't install Windows 11

0xC1900101 0x40017
The installation failed in the SECOND_BOOT phase with an error during BOOT operation

General troubleshooting:
  chkdsk c: /r
  sfc /scannow
  dism /online /cleanup-image /restorehealth
  net stop wuauserv && rmdir /S /Q C:\Windows\SoftwareDistribution\
  (check for driver and firmware updates)
  (check Windows Defender for issues)

Note: PxHlpa64.sys appears to be directly related to the Adobe Creative Cloud Desktop app,
      and has been an ongoing issue since 2022. The driver files are associated with Roxio
      software, but are installed with Adobe. AFAIK there's no harm in deleting the files.
#>

# Test for elevation
[Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
$Elevated = $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

$PX = "pxhlpa64"
$FilePaths = @(
  "C:\Windows\System32\drivers"
  "C:\Windows\CatRoot"
  "C:\Program Files (x86)\Common Files\Sonic Shared\PX Drivers"
)
$FileExts = @(
  "sys"
  "cat"
)

$PxService = (Get-Service -Name "$PX" -ErrorAction SilentlyContinue)

If ($PxService) {
  Write-Verbose "$PX service found. Attempting to delete..."
  try {
    Write-Verbose "sc delete $PX"
    Start-Process -FilePath "$((Get-Command -Name sc).Source)" -ArgumentList "delete $PX" -NoNewWindow -Wait
  } catch {
    $ErrorMsg = $_.ErrorDetails.Message
    Write-Error "$ErrorMsg"
  }
} Else {
  Write-Output "$PX service not installed."
}

ForEach ($FilePath in $FilePaths) {
  ForEach ($FileExt in $FileExts) {
    $ThisFile = "$FilePath\$PX.$FileExt"
    If (Test-Path -Path "$ThisFile") {
      try {
        Write-Verbose "Discovered $ThisFile"
        Remove-Item -Path "$ThisFile" -Force -Confirm:$False
        Write-Output "SUCCESS: Eliminated $ThisFile"
      } catch {
        $ErrorMsg = $_.ErrorDetails.Message
        Write-Error "$ErrorMsg"
      }
    } Else {
      Write-Verbose "No file at $ThisFile"
    }
    Remove-Variable -Name ThisFile -Force -ErrorAction SilentlyContinue
  }
}

Write-Output "$PX removal complete."
Exit 0
