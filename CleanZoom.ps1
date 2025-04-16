#==================================================
# Name     : CleanZoom.ps1
# Synopsis : Powershell version of CleanZoom.exe by Zoom
# Updated  : 2023-12-13 => script created
#==================================================

Set-StrictMode -Version Latest

# Check for elevation
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

$Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS

Resolve-Path "C:\Users\*\AppData\Roaming\Zoom" | ForEach-Object { Remove-Item -Path $_ -Recurse -Force -Confirm:$False }
Resolve-Path "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Zoom" | ForEach-Object { Remove-Item -Path $_ -Recurse -Force -Confirm:$False }
Resolve-Path "HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX" | ForEach-Object { Remove-Item $_ -Force }

Remove-PSDrive -Name HKU