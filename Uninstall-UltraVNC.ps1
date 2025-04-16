#==================================================
# Name     : Uninstall-UltraVNC.ps1
# Synopsis : Remove Ultra VNC
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

[CmdletBinding()]
Param();

Set-StrictMode -Version Latest

$UninstallPaths = @(
  "C:\Program Files\uvnc bvba\UltraVNC\unins000.exe",
  "C:\Program Files (x86)\uvnc bvba\UltraVNC\unins000.exe"
)

If (!(Test-Path $($UninstallPaths[0])) -and !(Test-Path $($UninstallPaths[1]))) {
  Write-Verbose "UltraVNC Uninstaller not present. Nothing to do."
  Exit 0
}

# Check for elevation
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

# Remove UltraVNC
ForEach ($UninstallPath in $UninstallPaths) {
  try {
    Start-Process -FilePath "$UninstallPath" -ArgumentList "/VERYSILENT /NORESTART" -Wait -NoNewWindow
  } catch { }  # nobody cares
}

Exit 0