#==================================================
# Name     : Protect-Server2016.ps1
# Synopsis : Apply common security recommendations to Windows Server 2016
# Updated  : 2025-04-16 => converted to Intune template
#==================================================

$Recommendations = @(
  @{"Description"   = "Disable 'Installation and configuration of Network Bridge on your DNS domain network'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
    "RegistryName"  = "NC_AllowNetBridge_NLA";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable IP source routing";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    "RegistryName"  = "DisableIPSourceRouting";
    "RegistryType"  = "Dword";
    "RegistryValue" = "2"
  };
  @{"Description"   = "Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";
    "RegistryName"  = "AllowLocalIPsecPolicyMerge";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable SMBv1 client driver";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10";
    "RegistryName"  = "Start";
    "RegistryType"  = "Dword";
    "RegistryValue" = "4"
  };
  @{"Description"   = "Enable 'Microsoft network client: Digitally sign communications (always)'";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    "RegistryName"  = "RequireSecuritySignature";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Set IPv6 source routing to highest protection";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
    "RegistryName"  = "DisableIPSourceRouting";
    "RegistryType"  = "Dword";
    "RegistryValue" = "2"
  };
)

ForEach ($Recommendation in $Recommendations) {
    $Description   = $Recommendation["Description"]
    $RegistryPath  = $Recommendation["RegistryPath"]
    $RegistryName  = $Recommendation["RegistryName"]
    $RegistryType  = $Recommendation["RegistryType"]
    $RegistryValue = $Recommendation["RegistryValue"]
  
    Write-Verbose "$Description" -Verbose
    try {
      If(!(Test-Path $RegistryPath)) { New-Item "$RegistryPath" -Force }
      [void](New-ItemProperty -Path $RegistryPath -Name $RegistryName -Value $RegistryValue -Type "$RegistryType" -Force)
      Write-Output "Set: $RegistryPath\$RegistryName ($RegistryType) = $RegistryValue"
    } catch {
      Write-Output "Failed! $RegistryPath\$RegistryName != $RegistryValue ($RegistryType)"
    }
  
    Remove-Variable -Name Description,RegistryPath,RegistryName,RegistryType,RegistryValue -Confirm:$False
  }
  
  Write-Output "All registry hacks have been implemented!"
  Exit 0