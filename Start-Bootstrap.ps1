#==================================================
# Name     : Start-Bootstrap.ps1
# Synopsis : Run common configuration tasks on a new machine
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

[CmdletBinding()] Param();
Set-StrictMode -Version Latest

Write-Verbose "Checking if PowerShell is elevated"
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity)
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator
$Elevated=$WindowsPrincipal.IsInRole($Administrator)
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; }

# Modify these values to fit your enviroment and setup needs!
Write-Verbose "Setting script-specific variables"
$RemoveFeatures     = @("Printing-Foundation", "Printing-XPSServices", "WorkFolders-Client")
$RemoveCapabilities = @("Browser.InternetExplorer", "Hello.Face", "Media.WindowsMediaPlayer", "Microsoft.Windows.WordPad", "SNMP.Client", "WMI-SNMP-Provider.Client", "XPS.Viewer")
$RemoveAppxPackages = @("GetStarted", "Clipchamp", "Microsoft3DViewer", "MicrosoftJournal", "MicrosoftFamily", "MicrosoftOfficeHub", "MicrosoftTeams", "MixedReality", "OneConnect", "OneNote", "OutlookForWindows", "Print3D", "QuickAssist", "SkypeApp", "Whiteboard", "WindowsCommunicationsApps", "WindowsFeedbackHub", "ZuneMusic")
$RemovePrinters     = @("OneNote", "Fax")
$RemoveLocalUsers   = @("LocalUser1", "Local User 2", "LocalUser 3")


Write-Verbose "Adding registry key for `'Console lock display off timeout`' in `'Power Options`'"
New-ItemProperty -Name "Attributes" -Value 2 -PropertyType "Dword" -Force `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7"
Write-Verbose "Adjusting power plan settings"
cmd /c "powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 300"     # "Turn off display after" on battery | 300 seconds = 5 minutes
cmd /c "powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 600"     # "Turn off display after" plugged in | 600 seconds = 10 minutes
cmd /c "powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 180"  # "Console lock display off timeout" on battery | 180 seconds = 3 minutes
cmd /c "powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 180"  # "Console lock display off timeout" plugged in | 180 seconds = 3 minutes
cmd /c "powercfg.exe /HIBERNATE OFF"



Write-Verbose "Preparing to remove unwanted Windows Optional Features"
ForEach ($Feature in $RemoveFeatures) {
  Get-WindowsOptionalFeature -Online | 
    Where-Object {$_.FeatureName -like "*$Feature*"} | 
      Disable-WindowsOptionalFeature -Online -Verbose:$VerbosePreference -Debug:$DebugPreference -NoRestart
}


Write-Verbose "Preparing to remove unwanted Windows Capabilities"
ForEach ($Capability in $RemoveCapabilities) {
  Get-WindowsCapability -Online | 
    Where-Object {($_.Name -like "*$Capability*") -and ($_.State -eq 'Installed')} |
      Remove-WindowsCapability -Online -Verbose:$VerbosePreference -Debug:$DebugPreference
}


Write-Verbose "Preparing to remove unwanted AppX Packages (Windows Store)"
ForEach ($Package in $RemoveAppxPackages) {
  Get-AppxProvisionedPackage -Online | 
    Where-Object {$_.DisplayName -like "*$Package*"} | 
      Remove-AppxProvisionedPackage -Online -Verbose:$VerbosePreference -Debug:$DebugPreference -ErrorAction SilentlyContinue
  Get-AppxPackage -AllUsers | 
    Where-Object {$_.Name -like "*$Package*"} | 
      Remove-AppxPackage -AllUsers -Confirm:$FALSE -Verbose:$VerbosePreference -Debug:$DebugPreference -ErrorAction SilentlyContinue
}


Write-Verbose "Preparing to remove unwanted built-in printers"
ForEach ($Printer in $RemovePrinters) {
  Remove-Printer -Name "*$Printer*" -Confirm:$FALSE -Verbose:$VerbosePreference -Debug:$DebugPreference
}

Write-Verbose "Setting label for C: to $($env:ComputerName)"
Set-Volume -DriveLetter $($env:SystemDrive)[0] -NewFileSystemLabel "$($env:ComputerName)"


Write-Verbose "Cleaning up local accounts"
ForEach ($Username in $RemoveLocalUsers) {
  $LocalUser = Get-LocalUser $Username -ErrorAction SilentlyContinue
  # If the user exists locally...
  If ($LocalUser) {
    $UserRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($LocalUser.SID)"
    # Delete the profile data from registry
    If ((Test-Path $UserRegistryPath) -and ($UserRegistryPath -ne "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\")) {
      $UserProfilePath = Get-ItemPropertyValue $UserRegistryPath ProfileImagePath
      Remove-Item $UserRegistryPath -Force -Confirm:$False
    }
    # Delete the user profile folder (usually at C:\Users\)
    If ((Test-Path variable:UserProfilePath) -and (Test-Path $UserProfilePath)) {
      Remove-Item $UserProfilePath -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Remove the local user account
    $LocalUser | Remove-LocalUser -Confirm:$False
  }
}

If ($PSScriptRoot -eq "C:\Temp") {
  Remove-Item -Path $PSCommandPath -Force
}

Write-Output "Please reboot this computer to finalize changes made by this script."
Exit 0
