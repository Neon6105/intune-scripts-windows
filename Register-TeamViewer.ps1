#==================================================
# Name     : Register-TeamViewer.ps1
# Synopsis : Register TeamViewer using an Assignment ID
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

# Configure Script-Specific Settings                                                                     # # # # # # # #
Set-StrictMode -Version Latest

# Get your assignment ID from https://login.teamviewer.com/nav/deploy/assignments
$TeamViewerAssignmentID = ''

try {
  # Assign TeamViewer to Family Life (x86)
  Write-Output "Attempting to assign TeamViewer from C:\Program Files (x86)\"
  Start-Process -FilePath "C:\Program Files (x86)\TeamViewer\TeamViewer.exe" -ArgumentList "assignment --id $TeamViewerAssignmentID" -Wait -NoNewWindow
  Exit 0
} catch {
  # Unable to find a 32-bit TeamViewer on a 64-bit system...
  $ErrorMsg = $_.Exception.Message
  Write-Error $ErrorMsg
}

try {
  # Assign TeamViewer to Family Life (32-on-32 or 64-on-64)
  Write-Output "Attempting to assign TeamViewer from C:\Program Files\"
  Start-Process -FilePath "C:\Program Files\TeamViewer\TeamViewer.exe" -ArgumentList "assignment --id $TeamViewerAssignmentID" -Wait -NoNewWindow
  Exit 0
} catch {
  # Unable to find a 32-on-32 or 64-on-64 version of TeamViewer
  $ErrorMsg = $_.Exception.Message
  Write-Error $ErrorMsg
}

# You have no chance to survive. Make your time.
Exit 1