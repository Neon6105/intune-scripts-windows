#==================================================
# Name     : Disable-TeamViewerMeetings.ps1
# Synopsis : Remove TeamViewer Meetings plugins for Outlook
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

# Configure Script-Specific Settings                                                                     # # # # # # # #
Set-StrictMode -Version Latest

# Check for elevation (optional)
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

$RegistryPaths = @(
  "HKLM:\SOFTWARE\Microsoft\Office\Outlook\AddIns\TeamViewerMeetingAddIn.AddIn",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\AddIns\TeamViewerMeetingAddIn.AddIn"
)
$RegistryName = "LoadBehavior"
$RegistryValue = 2
$RegistryType = "Dword"

ForEach ($RegistryPath in $RegistryPaths) {
  If (!(Test-Path $RegistryPath)) {
    Write-Output "Skipped $RegistryPath"
    Break;
  }
  Write-Output "Set: $RegistryPath\$RegistryName ($RegistryType) = $RegistryValue"
  try {
  [void](New-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Type "$RegistryType" -Force)
  } catch {
    $ErrorMsg = $_.Exception.Message
    Write-Error $ErrorMsg
    Exit 1
  }
}

Write-Output "Script complete!"
Exit 0
