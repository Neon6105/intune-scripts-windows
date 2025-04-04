[CmdletBinding()]
Param();

# Configure Script-Specific Settings                                                                     # # # # # # # #
Set-StrictMode -Version Latest

# Check for elevation (optional)
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

# PowerShell Script                                                                                      # # # # # # # #
$TeamsMsi = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"  # Teams Machine-Wide Installer
$UsersDir = "C:\Users"
$TeamsDir = "AppData\Local\Microsoft\Teams\"
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

# Uninstall Teams Machine-Wide Installer
try {
  Write-Verbose "Checking if Teams Machine-Wide Installer is installed"
  $installed = (Get-CimInstance -ClassName Win32_Product | Where-Object { $_.IdentifyingNumber -eq "$TeamsMsi" })
  If ($installed) {
    Write-Verbose "Running uninstaller for Teams Machine-Wide Installer"
    Start-Process "msiexec" -ArgumentList "/x $TeamsMsi /qn" -Wait
  }
} catch {
  $ErrorMsg = $_.Exception.Message
  Write-Error $ErrorMsg
  Exit 1
} finally {
  Write-Verbose "Waiting 2 seconds..."
  Start-Sleep -Seconds 2
  $still_installed = (Get-CimInstance -ClassName Win32_Product | Where-Object { $_.IdentifyingNumber -eq "{$TeamsMsi}" })
  If ($still_installed) { Write-Output "Teams Machine-Wide Installer was still detected!"; Exit 1; }
}

# Cleanup AppData ForEach
ForEach ($Path in (Resolve-Path -Path "$UsersDir\*\$TeamsDir")) {
  Write-Verbose "Cleaning $Path"
  Remove-Item -Path "$Path" -Recurse -Force
}

# Cleanup Registry ForEach
ForEach ($Path in (Resolve-Path -Path "$UsersReg\*\$TeamsReg")) {
  Write-Verbose "Cleaning $Path"
  Remove-Item -Path "$Path" -Force
}

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
  If (Test-Path -Path "C:\Users\$User\$TeamsDir") { Remove-Item -Path "C:\Users\$User\$TeamsDir" -Recurse -Force }
}
Remove-PSDrive -Name HKU -Force
Exit 0
