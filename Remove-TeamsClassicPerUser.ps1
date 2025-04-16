#==================================================
# Name     : Remove-TeamsClassicPerUser.ps1
# Synopsis : Remove Teams (classic) installed to %LocalAppData%
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

[CmdletBinding()]
Param();

Set-StrictMode -Version Latest

$Evidence = @(
  "$env:LocalAppData\Microsoft\Teams\",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
)

ForEach ($Path in $Evidence) {
  try {
    If (Test-Path -Path "$Path") { Remove-Item -Path "$Path" -Recurse -Force }
  } catch {
    $ErrorMsg = $_.Exception.Message
    Write-Error $ErrorMsg
    Exit 1
  }
}

Write-Output "Process complete!"
Exit 0