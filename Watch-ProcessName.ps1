[CmdletBinding()]
Param(
  [Parameter(Mandatory=$FALSE)]
  [string]$Seconds = 0
);

<# Installation instructions:
- Copy this script to C:\ProgramData\Scripts\
- Edit the variables below for the specific process to monitor and restart
- Rename the script, replacing ProcessName with the $ProcessName variable below
- Create a scheduled task to run this script as the required user
  - e.g., Program/script: powershell.exe
          Add arguments : -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\Scripts\Watch-ProcessName.ps1"

Note: Do not use the -Seconds parameter when unattended! It is for interactive use only.
#>

Set-StrictMode -Version Latest

$FilePath = "C:\Program Files\WorkingDirectory\ProcessName.exe"
$ProcessName = (Split-Path -Path "$FilePath" -Leaf).split(".exe")[0]
$WorkingDirectory = Split-Path -Path "$FilePath" -Parent

function Watchdog() {
  $IsRunning = (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)

  If ($IsRunning) {
    Write-Output "$(Get-Date) $ProcessName is already running!"
  } else {
    Write-Output "$(Get-Date) Starting $ProcessName"
    Write-Verbose "     ProcessName : $ProcessName"
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


# Notify of continuous monitoring if $Seconds are >= 1; else run once
If ($Seconds -ge 1) {
  Write-Output "Running continuously every $Seconds seconds. Use CTRL+C to break."
} else {
  Watchdog
}

# Continuous monitoring because $Seconds are >= 1
While ($Seconds -ge 1) {
  Watchdog
  Start-Sleep -Seconds $Seconds
}
