#==================================================
# Name     : SecurityRecommendationsRegistry.ps1
# Synopsis : Defender > Endpoints > Vulnerability Management > Recommendations
# Updated  : 2023-12-12 => script created
#==================================================

Exit 0
<#
  # Related component
  # Associated script
  @{"Description"   = "";
    "RegistryPath"  = "";
    "RegistryName"  = "";
    "RegistryType"  = "";
    "RegistryValue" = ""
  };
#>

$Recommendations = @(
  # Accounts
  @{"Description"   = "Disable the local storage of passwords and credentials";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
    "RegistryName"  = "DisableDomainCreds";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Enable Local Admin password management";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd";
    "RegistryName"  = "AdmPwdEnabled";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };

  # Application (Adobe Acrobat)
  # AdobeAcrobatSecurity_remediate.ps1
  @{"Description"   = "Disable Flash on Adobe Reader DC";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown";
    "RegistryName"  = "bEnableFlash";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable JavaScript on Adobe Reader DC";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown";
    "RegistryName"  = "bDisableJavaScript";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Disable JavaScript on Adobe DC";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown";
    "RegistryName"  = "bDisableJavaScript";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Disable JavaScript on Adobe Acrobat 2017";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Adobe\Acrobat\2017\FeatureLockDown";
    "RegistryName"  = "bDisableJavaScript";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };

  # Application (Google Chrome)
  # Configuration profile: Browser Google Chrome
  @{"Description"   = "Disable 'Continue running background apps when Google Chrome is closed'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Google\Chrome";
    "RegistryName"  = "BackgroundModeEnabled";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable 'Password Manager'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Google\Chrome";
    "RegistryName"  = "PasswordManagerEnabled";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };

  # Application (Internet Explorer)
  # Configuration profile: Browser Microsoft Edge
  @{"Description"   = "Disable running or installing downloaded software with invalid signature";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download";
    "RegistryName"  = "RunInvalidSignatures";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Block outdated ActiveX controls for Internet Explorer";
    "RegistryPath"  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext";
    "RegistryName"  = "VersionCheckEnabled";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };

  # Application (Microsoft Office)
  # Configuration profile: Baseline Computers Profile
  @{"Description"   = "Enable 'Hide Option to Enable or Disable Updates'";
    "RegistryPath"  = "HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate";
    "RegistryName"  = "hideenabledisableupdates";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };

  # Network
  # Configuration profile: Network Security Recommendations
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
  @{"Description"   = "Enable 'Require domain users to elevate when setting a network's location'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
    "RegistryName"  = "NC_StdDomainUserSetLocation";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Set IPv6 source routing to highest protection";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
    "RegistryName"  = "DisableIPSourceRouting";
    "RegistryType"  = "Dword";
    "RegistryValue" = "2"
  };
  @{"Description"   = "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
    "RegistryName"  = "LmCompatibilityLevel";
    "RegistryType"  = "Dword";
    "RegistryValue" = "5"
  };
  @{"Description"   = "Prohibit use of Internet Connection Sharing on your DNS domain network";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
    "RegistryName"  = "NC_ShowSharedAccessUI";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };

  # Operating System
  # Configuration profile: OS Security Recommendations
  @{"Description"   = "Disable 'Allow Basic authentication' for WinRM Client";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client";
    "RegistryName"  = "AllowBasic";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable 'Allow Basic authentication' for WinRM Service";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
    "RegistryName"  = "AllowBasic";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable Anonymous enumeration of shares";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
    "RegistryName"  = "RestrictAnonymous";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Disable 'Enumerate administrator accounts on elevation'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI";
    "RegistryName"  = "EnumerateAdministrators";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable Solicited Remote Assistance";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    "RegistryName"  = "fAllowToGetHelp";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Enable 'Apply UAC restrictions to local accounts on network logons'";
    "RegistryPath"  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    "RegistryName"  = "LocalAccountTokenFilterPolicy";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Enable 'Local Security Authority (LSA) protection'";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
    "RegistryName"  = "RunAsPPL";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Set User Account Control (UAC) to automatically deny elevation requests";
    "RegistryPath"  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    "RegistryName"  = "ConsentPromptBehaviorUser";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };

  # Security controls
  # ??
  @{"Description"   = "Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";
    "RegistryName"  = "AllowLocalIPsecPolicyMerge";
    "RegistryType"  = "Dword";
    "RegistryValue" = "0"
  };
  @{"Description"   = "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile";
    "RegistryName"  = "DisableNotifications";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile";
    "RegistryName"  = "DisableNotifications";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile";
    "RegistryPath"  = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile";
    "RegistryName"  = "DisableNotifications";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"
  };
  @{"Description"   = "Set controlled folder access to enabled or audit mode";
    "RegistryPath"  = "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
    "RegistryName"  = "EnableControlledFolderAccess";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"  # 1=enabled; 2=audit
  };
  # https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg#enable-credential-guard
  @{"Description"   = "Turn on Microsoft Defender Credential Guard";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard";
    "RegistryName"  = "EnableVirtualizationBasedSecurity";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"  # Enable Virtualization Based Security
  };
  @{"Description"   = "Turn on Microsoft Defender Credential Guard";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard";
    "RegistryName"  = "RequirePlatformSecurityFeatures";
    "RegistryType"  = "Dword";
    "RegistryValue" = "1"  # 1 = Secure Boot; 3 = Secure Boot and DMA protection
  };
  @{"Description"   = "Turn on Microsoft Defender Credential Guard";
    "RegistryPath"  = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard";
    "RegistryName"  = "LsaCfgFlags";
    "RegistryType"  = "Dword";
    "RegistryValue" = "2"  # Credential Guard 1 = with UEFI lock; 2 = without lock
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