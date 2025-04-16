#==================================================
# Name     : Remove-Enrollment.ps1
# Synopsis : Remove Intune enrollment data from the local machine
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

Set-StrictMode -Version Latest

# Check for elevation
$WindowsIdentity=[System.Security.Principal.WindowsIdentity]::GetCurrent();
$WindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$Administrator=[System.Security.Principal.WindowsBuiltInRole]::Administrator;
$Elevated=$WindowsPrincipal.IsInRole($Administrator);
If (! $Elevated) { Write-Error "Administrative rights required! Please elevate PowerShell then try again."; Exit 1; };

# PowerShell Script                                                                                      # # # # # # # #
$EnrollmentRegistry = "HKLM:\SOFTWARE\Microsoft\Enrollments"

try {
  $TaskPath = (Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\*" -TaskName "Login*").TaskPath
  Write-Output "      TaskPath : $TaskPath"
  $EnrollmentGUID = $TaskPath.Split("\")[-2]
  Write-Output "EnrollmentGUID : $EnrollmentGUID"
  If ($EnrollmentGUID -notmatch '.{8}-.{4}-.{4}-.{4}-.{12}') { throw "GUID does not match pattern" }
  $EnrollmentPath = "$EnrollmentRegistry\$EnrollmentGUID"
  Write-Output "EnrollmentPath : $EnrollmentPath"
  If ($EnrollmentPath -ne "$EnrollmentRegistry\") {
    Write-Output "Removing EnrollmentPath from registry"
    Remove-Item -Path $EnrollmentPath -Force -Recurse -Confirm:$False
  } else { throw "EnrollmentPath mismatch!" }
  Exit 0
} catch {
  $ErrorMsg = $_.Exception.Message
  Write-Error $ErrorMsg
  Exit 1
}

# Something didn't go as planned...
Write-Output "You shouldn't be here."
Exit 1