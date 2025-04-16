#==================================================
# Name     : Remove-TeamsClassicRegistryOnly.ps1
# Synopsis : Remove references to Microsoft Teams (classic) from the registry
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

[CmdletBinding()]
Param();

# Configure Script-Specific Settings                                                                     # # # # # # # #
Set-StrictMode -Version Latest

# PowerShell Script                                                                                      # # # # # # # #
$UsersDir = "C:\Users"
$UsersReg = "HKU:"
$TeamsReg = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
$UserProfiles = (Get-ChildItem -Path "$UsersDir\" -Exclude Public).Name

$SignedInUsers = @();
$SignedInUsers += $env:USERNAME;
$SignedInUsers += (query user | `
  ForEach-Object { $_.Trim() -replace "IDLE TIME","IDLETIME" } | `
  ForEach-Object { $_.Trim() -replace "LOGON TIME","LOGONTIME" } | `
  ForEach-Object { $_.Trim() -replace "\s+","," } | `
  ForEach-Object { $_.Trim() -replace ">","" } | `
  ConvertFrom-Csv).Username

New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS

# Duplicate cleaups per User
ForEach ($User in $UserProfiles) {
  # Load User Registry
  If ($User -eq $env:USERNAME) {
    Write-Verbose "Searching HKCU:\"
    $UsersReg = "HKCU:"
  } else {
    Write-Verbose "Searching HKU:\$User\"
    $UsersReg = "$UsersReg\$User"
    If ((Test-Path $UsersDir\$User\NTUSER.DAT) -and ($User -notin $SignedInUsers)) {
      Write-Verbose "Loading registry for $User"
      try { cmd /c "reg load HKU\$User $UsersDir\$User\NTUSER.DAT" } catch {};
    }
  }
  # Clean User Registry
  If (Test-Path -Path "$UsersReg\$TeamsReg") {
    Write-Verbose "Cleaning $UsersReg\$TeamsReg"
    Remove-Item -Path "$UsersReg\$TeamsReg" -Force
  }
  # Unload User Registry
  If ((Test-Path $UsersDir\$User\NTUSER.DAT) -and ($User -notin $SignedInUsers)) {
    try {
      Write-Verbose "Unloading registry for $User"
      cmd /c "reg unload HKU\$User"
    } catch {
      # Do nothing; we don't care
    }
  }
}
Remove-PSDrive -Name HKU -Force
Exit 0