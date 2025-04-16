#==================================================
# Name     : Copy-AuditionSettings.ps1
# Synopsis : Copy Adobe Audition settings to a new location
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True,Position=1)]
  [string]$Source,
  [Parameter(Mandatory=$True,Position=2)]
  [string]$Destination,
  [switch]$Favorites,
  [switch]$Shortcuts
);

# Configure Script-Specific Settings                                                                     # # # # # # # #
Set-StrictMode -Version Latest

# Check for elevation (optional)
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

# Initialize Script (Local) Variables                                                                            # # # #
$SourceUser, $SourcePC = $Source.Split('@')
$DestinationUser, $DestinationPC = $Destination.Split('@')
$AuditionRoot = "AppData\Adobe\Audition\*"

If ($SourcePC -eq $env:ComputerName) { $SourcePC = "localhost" }
If ($DestinationPC -eq $env:ComputerName) { $DestinationPC = "localhost" }
If ((!$Favorites) -and (!$Shortcuts)) { $Favorites = $Shortcuts = $True }

$AuditionSource = (Resolve-Path -Path "\\$SourcePC\C$\Users\$SourceUser\$AuditionRoot" | Sort-Object -Property Path | Select-Object -Last 1)
$AuditionDestination = (Resolve-Path -Path "\\$DestinationPC\C$\Users\$DestinationUser\$AuditionRoot" | Sort-Object -Property Path | Select-Object -Last 1)

If (! (Test-Path $AuditionSource)) {
  Write-Output "Cannot find source file! Check $SourceUser on $SourcePC"
  Write-Verbose "$AuditionSource"
}

If (! (Test-Path $AuditionDestination)) {
  Write-Output "Cannot find destination path! Check $DestinationUser on $DestinationPC"
  Write-Verbose "$AuditionDestination"
}

If ($Favorites) {
  Copy-Item -Path "$AuditionSource\favorites.xml" -Destination "$AuditionDestination" -Force
}

If ($Shortcuts) {
  Copy-Item -Path "$AuditionSource\Shortcuts\" -Destination "$AuditionDestination" -Recurse -Force
}