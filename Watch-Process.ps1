[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True,Position=1)]
  [string]$FilePath,
  [Parameter(Mandatory=$False)]
  [string]$Name,
  [Parameter(Mandatory=$False)]
  [string]$WorkingDirectory,
  [Parameter(Mandatory=$False)]
  [string]$Seconds = 0
);

<# Installation instructions:
- Copy this script to C:\ProgramData\Scripts\
- Create a scheduled task to run this script as the required user
  - e.g., Program/script: powershell.exe
          Add arguments : -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\Scripts\Watch-Process.ps1" -Name "ProcessName" -FilePath "C:\Path\To\ProcessName.exe"

Note: Do not use the -Seconds parameter when unattended! It is for interactive use only.
#>

Set-StrictMode -Version Latest

# Verify that the specified file exists
If (!(Test-Path -Path "$FilePath" -PathType Leaf)) {
  Write-Error "The requested file could not be found. Watchdog will be unable to restart the process."
  Exit 1
}

# Determine $Name from the $FilePath
# Use Split-Path to get the name of the file (Leaf) then split the file name to remove '.exe'
If (!($Name)) { $Name = (Split-Path -Path "$FilePath" -Leaf).split(".exe")[0] }

# Verify or set the working directory
If (!($WorkingDirectory) -or !(Test-Path -Path "$WorkingDirectory" -PathType Container)) {
  $WorkingDirectory = Split-Path -Path "$FilePath" -Parent
}

function Watchdog() {
  $IsRunning = (Get-Process -Name $Name -ErrorAction SilentlyContinue)

  If ($IsRunning) {
    Write-Output "$(Get-Date) $Name is already running!"
  } else {
    Write-Output "$(Get-Date) Starting $Name"
    Write-Verbose "            Name : $Name"
    Write-Verbose "        FilePath : $FilePath"
    Write-Verbose "WorkingDirectory : $WorkingDirectory"
    try {
      Start-Process -FilePath "$FilePath" -WorkingDirectory "$WorkingDirectory"
    } catch {
      $ErrorMsg = $_.Exception.Message
      Write-Error $ErrorMsg
    }
  }
}


If ($Seconds -ge 1) {
  Write-Output "Running continuously every $Seconds seconds. Use CTRL+C to break."
} else {
  Watchdog
}

While ($Seconds -ge 1) {
  Watchdog
  Start-Sleep -Seconds $Seconds
}
