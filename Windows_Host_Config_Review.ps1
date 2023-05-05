
write-host "Starting Host Configuration Check  `n" -ForegroundColor Black -BackgroundColor Green
$h="$env:COMPUTERNAME"
$ErrorActionPreference = 'SilentlyContinue'


##########################################################################################################################
#Checks to see if powershell script is running as Administrator and if not relaunches an elevated powershell script.
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
   
    Write-Host "You are about to run this script without Administrator privileges.`nIf you run this script without Administrator privileges, several checks will be skipped." -ForegroundColor Yellow -Backgroundcolor Black
	$Proceed = Read-Host "Would you like to elevate to Administrator privileges? (yes or no) `n"
	while("yes","no" -notcontains $Proceed)
	{
		$Proceed = Read-Host "Yes or No"
	}
    if ($Proceed -eq "no") {
        Write-Host "Continuing ..." -ForegroundColor Green
    }
    elseif ($Proceed -eq "yes") {
	    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$PSScriptRoot'; & '$PSCommandPath';`"";
        
    }
  
}
##########################################################################################################################
#Determine type of Operating System
try {
	$global:DomainRole = (Get-Wmiobject -Class 'Win32_computersystem').domainrole
    if ($DomainRole -eq 0) {$OS = "Standalone Workstation"}
    if ($DomainRole -eq 1) {$OS = "Member Workstation"}
	if ($DomainRole -eq 2) {$OS = "Standalone Server"}
	if ($DomainRole -eq 3) {$OS = "Member Server"}
	if ($DomainRole -eq 4) {$OS = "Backup Domain Controller"}
	if ($DomainRole -eq 5) {$OS = "Primary Domain Controller"}
	Write-Host "This system is a $OS `n" -ForegroundColor Yellow
}
catch {
    Write-Host "The system type could not be detected" -ForegroundColor Red
}
$OperatingSystem = (Get-WmiObject -class win32_operatingsystem).Caption 

$DNSHost = Read-Host "Enter domain for DNS Exfiltration check"

##########################################################################################################################

#Gather computer Details

Get-ComputerInfo | Select WindowsCurrentVersion, WindowsEditionId, WindowsInstallationType, WindowsProductName, WindowsRegisteredOrganization, CsCaption, CsDNSHostName, CsDomain, CsNetworkAdapters, CsUserName, OsName, OsType, OsOperatingSystemSKU, OsVersion, OsBootDevice, OsNumberOfUsers, LogonServer , DeviceGuardSmartStatus
##########################################################################################################################

#Enuerate Users and Group
"List of all Users and Groups" >> "$h.UserandGroup"
write-host("Gathering  all Users and Groups and writes to a file in format <hostname>.UserandGroup  `n")  -ForegroundColor Cyan
#Get-WmiObject -Class Win32_UserAccount >> "$h.UserandGroup"
net localgroup  >> "$h.UserandGroup"
net localgroup Administrators >> "$h.UserandGroup"
whoami /all >> "$h.UserandGroup"

##########################################################################################################################

#Unquoted Service Paths
write-host("Gathering  allunquoted service path and writes to a file in format <hostname>.UnquotedService  `n")  -ForegroundColor Cyan
"Unquoted Service Paths - If the path to an executable is not inside quotes, Windows will try to execute every ending before a space.


Reference: https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae
https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths" >> "$h.UnquotedService"
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name >> "$h.UnquotedService"

##########################################################################################################################

#Winlogon Credentials
write-host("Gathering  all winlogon registry stored credentials  and writes to a file in format <hostname>.WinlogonCred `n")  -ForegroundColor Cyan
"Stored Winlogon Credential in winlogon registry" >> "$h.WinlogonCred"
Get-Content "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  -Name DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername >> "$h.WinlogonCred"

##########################################################################################################################

#Password Policy
write-host("Gathering password policy and write to a file in format <hostname>.passwordpolicy `n")  -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy >> "$h.passwordpolicy"
net accounts /domain >> "$h.passwordpolicy"
"Reference: https://www.nzism.gcsb.govt.nz/ism-document/#1857 #Password length
https://www.nzism.gcsb.govt.nz/ism-document/#1868 #Password age" >> "$h.passwordpolicy"

##########################################################################################################################

#Applocker Policy
write-host("Gathering effective Applocker policy and writes to a file in format <hostname>.Applocker_Policy  `n")  -ForegroundColor Cyan
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections | out-file -FilePath "$h.Applocker_Policy"

##########################################################################################################################

#Bitlocker Info
write-host("Gathering Bitlocker Policy - Requires Administrative Privelege to run. Gets information about volumes that BitLocker Drive Encryption can protect and writes to a file in format <hostname.Bitlocker>  `n")  -ForegroundColor Cyan
manage-bde -status >> "$h.Bitlocker"
Get-BitLockerVolume >> "$h.Bitlocker"

##########################################################################################################################

#Running Process Info
write-host("Gathering detailed list of running processes and writes to a file in format <hostname.Detailed_Process>  `n")  -ForegroundColor Cyan
Get-WmiObject Win32_Process >> "$h.Detailed_Process"
Get-Process >> "$h.Detailed_Process"

##########################################################################################################################

#DNS Exfiltration Test
write-host("DNS Exfiltration test and writes to a file in format <hostname.DNS_Exfil>  `n")  -ForegroundColor Cyan
write-host("Execute DNS lookup via Google, Cloudflare and OpenDNS external DNS `n")
$dnsdomain= $DNSHost
nslookup $dnsdomain >> "$h.DNS_Exfil"
nslookup 8.8.8.8  >> "$h.DNS_Exfil" 
nslookup  1.1.1.1  >> "$h.DNS_Exfil" 
nslookup 208.67.222.222  >> "$h.DNS_Exfil"

##########################################################################################################################

#Gathers Environment variable
write-host("Gathering System environment variable list and writes to a file in format <hostname.Env_variable>  `n ")  -ForegroundColor Cyan
"Reference: https://attack.mitre.org/techniques/T1574/007/ `n" >> "$h.Env_variable"
Get-ChildItem Env: | Format-Table -Wrap  >> "$h.Env_variable"

##########################################################################################################################

#Gathers Firewall settings
write-host("Gathering Firewall setting and rules. Writes to a file in format <hostname.Firewall_output>  `n")  -ForegroundColor Cyan
"List of all Firewall setting " >> "$h.Firewall_output"
ls 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\' >> "$h.Firewall_output"
"List of all Firewall Rules" >> "$h.Firewall_output"
netsh advfirewall firewall show rule all >> "$h.Firewall_output"
"List of all Firewall profiles" >> "$h.Firewall_output"
netsh advfirewall show allprofiles >> "$h.Firewall_output"

##########################################################################################################################

#Gathers Group Policy 
write-host("Gathering Group Policy. Writes to a file in format <GPResults.html>  `n")  -ForegroundColor Cyan 
GPRESULT  /H  "$h.gpresult.html"

##########################################################################################################################

#Gathers installed application
write-host("Gathering list of installed application. Writes to a file in format <hostname.Installed_App>  `n") -ForegroundColor Cyan 
Get-WmiObject -Class Win32_Product | select Name, Version  >> "$h.Installed_App"
wmic product list /format:csv | Format-Table Wrap >> "$h.Installed_App"
#Gathers installed application based on registry key value. Helpful to gathers even missed application through above commands.
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | % {Get-ItemProperty $_.PsPath} | where {$_.Displayname -and ($_.Displayname -match ".*")} |sort Displayname | select DisplayName, DisplayVersion,InstallDate, @{Name="Server";Expression={$env:computername}} >> "$h.Installed_App"

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |Where-Object displayname -ne $null| Select-Object DisplayName, DisplayVersion,InstallDate,@{Name="Server";Expression={$env:computername}}|select DisplayName, DisplayVersion,InstallDate, @{Name="Server";Expression={$env:computername}} >> "$h.Installed_App"

##########################################################################################################################

#Gathers Network configuration
write-host("Gathering Network File. Writes to a file in format <hostname.Network_File>  `n")  -ForegroundColor Cyan
"IPconfig - Displays all current TCP/IP network configuration values and refreshes Dynamic Host Configuration Protocol (DHCP) and Domain Name System (DNS) settings."  >> "$h.Network_File"
ipconfig /all  >> "$h.Network_File"
"Displays the entries in the local IP routing table."  >> "$h.Network_File"
route print >> "$h.Network_File"
"ARP Details" >> "$h.Network_File"
arp -A >> "$h.Network_File"
"Displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics (for the IP, ICMP, TCP, and UDP protocols), and IPv6 statistics (for the IPv6, ICMPv6, TCP over IPv6, and UDP over IPv6 protocols)." >> "$h.Network_File"
netstat -anob  >> "$h.Network_File"

##########################################################################################################################

#Gathers Powershell history of all users
write-host("Collects  powershell history for all users, and display with the associated ACL for the file. Writes to a file in format <hostname.History>  `n")  -ForegroundColor Cyan
Get-ChildItem C:\Users | ForEach-Object { "$($_.FullName)\AppData\Roaming", "$($_.FullName)\AppData\Local" } | ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter "ConsoleHost_history.txt" -ErrorAction SilentlyContinue } | ForEach-Object { echo "----------"; Get-Acl -Path $_.FullName | Format-Table -Wrap; echo "----------"; Get-Content $_.FullName } >> "$h.History"

##########################################################################################################################

#Gathers RDP Files
write-host("Gatehring RDP File.  Writes to a file in format <hostname.RDP>  `n")  -ForegroundColor Cyan
"Remote Desktop Services must be configured with the client connection encryption set to High Level as below 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
Value Name: MinEncryptionLevel
Type: REG_DWORD
Value: 0x00000003 (3).
Value Name: SecurityLayer
Type: REG_DWORD
Value: 0x00000002 (2)" >> "$h.RDP"
"SecurityLayer specifies how servers and clients authenticate each other before a remote desktop connection is established and the value should be 2. 
Reference: 
https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
https://www.stigviewer.com/stig/windows_server_2019/2020-06-15/finding/V-92973"  >> "$h.RDP"
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' | Select SecurityLayer, MinEncryptionLevel >> "$h.RDP"
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' >> "$h.RDP"

##########################################################################################################################

#Some Crucial  Checks

write-host ("===================     Starting Some Crucial  Checks and write it to file <hostname.RegularChecks>     ========================== `n"  ) -ForegroundColor Green

"=================================================================================================================" >> "$h.RegularChecks"
#LSA Anonymous access - To secure Windows NT against “Null Session” exploit
$LsaAnonymousAccess=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' | select RestrictAnonymous
write-host ("Checking LSA Anonymous Access `n"  ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name RestrictAnonymous >> "$h.RegularChecks"
if ($LsaAnonymousAccess.RestrictAnonymous -eq 1)
{
"PASS - Anonymous enumeration of shares has not been allowed.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - Anonymous enumeration of shares must not be allowed  `n
Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.`n
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
Value Name: RestrictAnonymous
Value Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://www.giac.org/paper/gcwn/17/secure-windows-nt-null-session-exploit/100311
https://www.tenable.com/plugins/nessus/26920 `n" >>  "$h.RegularChecks"

}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable the local storage of passwords and credentials

$domaincred=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' | select disabledomaincreds
write-host ("Checking if system  configured to prevent the storage of passwords and credentials. `n"  ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name disabledomaincreds >> "$h.RegularChecks"
if ($domaincred.disabledomaincreds -eq 1)
{
"PASS - Credential Manager does not save any password.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - Disable the local storage of passwords and credentials `n
Locally cached passwords or credentials can be accessed by malicious code or unauthorized users. This setting controls the storage of passwords and credentials for network authentication on the local system. Such credentials must not be stored on the local machine, as that may lead to account compromise.`n
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
Value Name: disabledomaincreds
Value Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://attack.mitre.org/techniques/T1003/004/
https://pentestlab.blog/2018/04/04/dumping-clear-text-credentials/ `n" >>  "$h.RegularChecks"

}

"=================================================================================================================" >> "$h.RegularChecks"


#Disable autoplay for non volume device
$Autoplay=Get-ItemProperty 'HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\Explorer\' | select  NoAutoplayfornonVolume
write-host ("Checking AutoPlay for non volume device `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\Explorer\' -Name  NoAutoplayfornonVolume >>  "$h.RegularChecks"

if ($Autoplay.NoAutoplayfornonVolume -eq 1)
{
"PASS - Anonymous enumeration of shares has not been allowed.`n" >>  "$h.RegularChecks"
}
else
{
"FAIL - AutoPlay must be turned off for non-volume devices - Applies to device where a external drive can be inserted else please ignore. 
Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for non-volume devices, such as Media Transfer Protocol (MTP) devices.`n
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
Value Name: NoAutoplayfornonVolume
Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://www.cyber.gov.au/sites/default/files/2021-10/PROTECT%20-%20Hardening%20Microsoft%20Windows%2010%20version%2021H1%20Workstations%20%28October%202021%29.pdf`n" >>  "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable AutoRun 
$Autorun=Get-ItemProperty 'HKLM:\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' | select NoAutorun
write-host ("Checking default Autorun behaviour `n" ) -ForegroundColor Green

if ($Autorun. NoAutorun -eq 1)

{
"PASS - Default Autorun behaviour has not been enabled.`n" >>  "$h.RegularChecks"
}
else
{
"FAIL - The default AutoRun behavior must be configured to prevent AutoRun commands - - Applies to device where a external drive can be inserted else please ignore.
Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing.`n
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
Value Name: NoAutorun
Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://www.trendmicro.com/vinfo/us/security/definition/autorun" >>  "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable AnonymousSAM Access
$AnonymousSAM=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' | select RestrictAnonymousSAM
write-host ("Checking Anonymous Enumeration of SAM  `n" ) -ForegroundColor Green
if ($AnonymousSAM. RestrictAnonymousSAM -eq 1)
{
"PASS - Anonymous enumeration of Security Account Manager (SAM) accounts has not been allowed.`n" >>  "$h.RegularChecks"
}
else
{
"FAIL - Anonymous enumeration of Security Account Manager (SAM) accounts must not be allowed. - HIGH" >> "$h.RegularChecks"
"Anonymous enumeration of SAM accounts allows anonymous logon users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.`n
If the following registry value does not exist or is not configured as specified, this is a finding:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
Value Name: RestrictAnonymousSAM
Value Type: REG_DWORD
Value: 0x00000001 (1)

Reference:https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check if Anti-virus Windefender is running
$Antivirus=Get-Service -Name windefend
write-host ("Checking Windows Defender or other AV Status  `n" ) -ForegroundColor Green
Get-Service -Name windefend >> "$h.RegularChecks"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more >> "$h.RegularChecks"


if ($Antivirus.Status -eq 'running')
{
"PASS - Anti-virus Windows Defender has been enabled and running.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - Antivirus Windows Defender not running.Check for other Antivirus present on host - MEDIUM"
"Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system. Install an anti-virus solution on the system.Please check if any other third party Antivirus program is inatlled and running`n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable Local BlankPassword
$BlankPassword=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'  | select LimitBlankPasswordUse
write-host ("Checking for local Blank Password  `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -Name LimitBlankPasswordUse >> "$h.RegularChecks"

if ($BlankPassword.LimitBlankPasswordUse -eq 1)
{
"PASS - Blank Passwords not allowed.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - Local accounts with blank passwords must be restricted to prevent access from the network
An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password does exist, enabling this setting will prevent network access, limiting the account to local console logon only.`n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check system version
$os_info=gwmi Win32_OperatingSystem
write-host ("Checking current system version  `n" ) -ForegroundColor Green
gwmi Win32_OperatingSystem  >> "$h.RegularChecks"

if ($os_info.BuildNumber -ge 14393)
{
"PASS - Updated version of OS in use.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - Systems must be maintained at a supported servicing level
Systems at unsupported servicing levels will not receive security updates for new vulnerabilities, which leave them subject to exploitation. Systems must be maintained at a servicing level supported by the vendor with new security updates.`n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable Windows Installer with elevated Privileges
$ElevatedPriv=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' | select  AlwaysInstallElevated
write-host ("Checking for Windows Installer Elevated Privilege  `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\' >> "$h.RegularChecks"
if ($ElevatedPriv.AlwaysInstallElevated -eq 0)
{
"PASS - The Windows Installer Always install with elevated privileges option has been disabled.`n" >> "$h.RegularChecks"
}
else
{
"FAIL - The Windows Installer Always install with elevated privileges option must be disabled. - Applies only if Applocker policy is not available in the host.
Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.`n 
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
Value Name: AlwaysInstallElevated
Type: REG_DWORD
Value: 0x00000000 (0)

Reference: https://pentestlab.blog/2017/02/28/always-install-elevated/" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check if WinRM is enabled in system

"Following checks are needed only if WinRM is enabled and running `n" >> "$h.RegularChecks"
Get-Service WinRM >> "$h.RegularChecks"

"=================================================================================================================" >> "$h.RegularChecks"
#DisableRunas for WinRM
$WinrRMRunas=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' | select DisableRunAs
write-host ("Checking if WinRM stores RunAs credentials `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' | select DisableRunAs >> "$h.RegularChecks"
if ($WinrRMRunas.DisableRunAs -eq 1)
{
"PASS -  The Windows Remote Management (WinRM) service does not store RunAs credentials.  `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The Windows Remote Management (WinRM) service must not store RunAs credentials. 
Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
Value Name: DisableRunAs
Type: REG_DWORD
Value: 0x00000001 (1) `n

Reference: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsRemoteManagement::DisableRunAs
https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-remotemanagement" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"


#Disable basic authentication in WinRM Service
$WinRMService=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' | select AllowBasic
write-host ("Checking if basic authentication enabled for WinRM Service  `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\' >> "$h.RegularChecks"
if ($WinRMService.AllowBasic -eq 0)
{
"PASS - The Windows Remote Management (WinRM) Service does not use Basic authentication.`n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The Windows Remote Management (WinRM) Service  must not use Basic authentication. 
Basic authentication uses plain-text passwords that could be used to compromise a system.  If WinRM is configured to use HTTP transport, the user name and password are sent over the network as clear text. Disabling Basic authentication will reduce this potential. `n
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Service\
Value Name: AllowBasic
Type: REG_DWORD
Value: 0

Reference: https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73599" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable basic authentication in WinRM Client
$WinRMClient=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' | select AllowBasic
write-host ("Checking if basic authentication enabled for WinRM Client `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\' >> "$h.RegularChecks"

if ($WinRMClient.AllowBasic -eq 0)
{
"PASS - The Windows Remote Management (WinRM) Client does not use Basic authentication.`n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The Windows Remote Management (WinRM) Client  must not use Basic authentication. 
Basic authentication uses plain-text passwords that could be used to compromise a system. If WinRM is configured to use HTTP transport, the user name and password are sent over the network as clear text. Disabling Basic authentication will reduce this potential. `n
If the following registry value does not exist or is not configured as specified, this is a finding:
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
Value Name: AllowBasic
Value Type: REG_DWORD
Value: 0

Reference: https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-63335" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"


#NTLMv2 LAN Manager authentication
$NTLMv2=Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' | select LmCompatibilityLevel
write-host ("Checking LAN Manager Authentication level `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\\SYSTEM\CurrentControlSet\Control\Lsa\' -Name LmCompatibilityLevel >> "$h.RegularChecks"
if ($NTLMv2.LmCompatibilityLevel -eq 5)
{
"PASS - The LAN Manager authentication level  set to send NTLMv2 response only. `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The LAN Manager authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM. 
The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to standalone computers that are running later versions.`n 
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
Value Name: LmCompatibilityLevel
Value Type: REG_DWORD
Value: 0x00000005 (5)

Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-levelhttps://www.crowdstrike.com/cybersecurity-101/ntlm-windows-new-technology-lan-manager/ `n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Restrict Anonymous Access to pipes and shares
$NullAccess=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' | select  RestrictNullSessAccess
write-host ("Checking Anonymous access to named pipes and shares `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\' -Name  RestrictNullSessAccess >> "$h.RegularChecks"
if ($NullAccess.RestrictNullSessAccess -eq 1)
{
"PASS - Anonymous access to Named Pipes and Shares has been restricted. `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  Anonymous access to Named Pipes and Shares must be restricted. 
Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This setting restricts access to those defined in Network access: Named Pipes that can be accessed anonymously and Network access: Shares that can be accessed anonymously, both of which must be blank under other requirements. `n 
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\
Value Name: RestrictNullSessAccess
Value Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable SMBV1
$SMBV1 = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' | select SMB1
write-host ("Checking if SMBV1 has been enabled `n" ) -ForegroundColor Green
Get-SmbServerConfiguration | Select EnableSMB1Protocol >> "$h.RegularChecks"

if ($SMBV1.SMB1 -eq 0)
{
"PASS - The Server Message Block (SMB) v1 protocol  disabled on the SMB client. `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The Server Message Block (SMB) v1 protocol must be disabled on the SMB client. 
SMBV1 is a legacy protocol and is vulnerable to multiple attacks. An attacker could use known exploits to compromise the server, capture credentials or destroy data.

Reference: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=smbv1
https://attack.mitre.org/techniques/T1210/`n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Inactivity timeout setting
$Inactivity = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' |  Select InactivityTimeoutSecs
write-host ("Checking inactivity timeout setting `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' |  Select InactivityTimeoutSecs >> "$h.RegularChecks"
if ($Inactivity.InactivityTimeoutSecs -le 900)
{
"PASS - Machine Timeout session is set properly `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  The machine inactivity limit must be set to 15 minutes, locking the system with the screen saver. 
Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.`n

Reference: https://www.nzism.gcsb.govt.nz/ism-document/#1802 16.1.44.C.01.Control: System Classification(s): All Classifications; Compliance: SHOULD [CID:1881]`n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Disable Password Saving for RDP CLient
$PassSaving=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' | select DisablePasswordSaving
write-host ("Checking if password saving is enabled for RDP `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' -Name DisablePasswordSaving >> "$h.RegularChecks"

if ($PassSaving.DisablePasswordSaving -eq 1)
{
"PASS -  PasswordSaving  disabled in the Remote Desktop Client  `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  Passwords must not be saved in the Remote Desktop Client. 
Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.
If the following registry value does not exist or is not configured as specified, this is a finding.
 
Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
Value Name: DisablePasswordSaving
Type: REG_DWORD
Value: 0x00000001 (1)

Reference: https://attack.mitre.org/techniques/T1021/001/ `n" >> "$h.RegularChecks"

}

"=================================================================================================================" >> "$h.RegularChecks"


" *****Important Following checks requires Get-WindowsFeature cmdlet, Check if Get-WindowsFeature is present in the host***** `n" >> "$h.RegularChecks"

#Check Powershell version2 installed
$powershellversion2=Get-WindowsFeature | Where Name -eq PowerShell-v2 
write-host ("Checking if Powershell version 2 has been installed `n" ) -ForegroundColor Green
Get-WindowsFeature | Where Name -eq PowerShell-v2 >> "$h.RegularChecks"
if ($powershellversion2.InstallState  -eq 'Available')
{
"PASS -  Windows PowerShell 2.0 has not been installed.   `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  Windows PowerShell 2.0 must not be installed
Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.

Reference: https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/
https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/
https://attack.mitre.org/techniques/T1562/010/ `n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check Telnet has been installed
$telnet=Get-WindowsFeature | Where Name -eq Telnet-Client
write-host ("Checking if Telnet has been installed `n" ) -ForegroundColor Green
Get-WindowsFeature | Where Name -eq Telnet-Client >> "$h.RegularChecks"
if ($telnet.InstallState  -eq 'Available')
{
"PASS -  Telnet has not been installed. `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  Telnet must not be installed 
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system. `n

Reference: https://it.mst.edu/policies/secure-telnet/#:~:text=Telnet%20is%20inherently%20insecure.,prevent%20this%20type%20of%20intrusion." >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check FTP has been installed

$ftp=Get-WindowsFeature | Where Name -eq Web-Ftp-Service
write-host ("Checking if FTP has been installed `n" ) -ForegroundColor Green
Get-WindowsFeature | Where Name -eq Web-Ftp-Service >> "$h.RegularChecks"
if ($ftp.InstallState  -eq 'Available')
{
"PASS -  FTP has not been installed. `n" >> "$h.RegularChecks"
}
else
{
"FAIL -  FTP must not be installed 
Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption or may provide unauthorized access to the system. `n

Reference: https://datatracker.ietf.org/doc/html/rfc2577" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check if Legal Notice and caption has been configured.

$legalnotice=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 
write-host ("Checking if Legal notice and caption has been configured `n" ) -ForegroundColor Green
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name LegalNoticeTexT, legalnoticecaption >> "$h.RegularChecks"
if ($legalnotice.LegalNoticeText  -ne $null)
{
"PASS -   The required legal notice has been configured. `n" >> "$h.RegularChecks"
}
else
{
"FAIL - The required legal notice must be configured to display before console logon. " >> "$h.RegularChecks"
"Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. 

Reference: https://www.nzism.gcsb.govt.nz/ism-document/#1901 16.1.48.C.03.Control: System Classification(s): All Classifications; Compliance: SHOULD [CID:1901] `n" >> "$h.RegularChecks"
}

if ($legalnotice.legalnoticecaption  -ne $null)
{
"PASS -   The required legal notice caption has been configured. `n" >> "$h.RegularChecks"
}
else
{
"FAIL - The required legal notice caption must be configured to display before console logon. " >> "$h.RegularChecks"
"Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. 

Reference: https://www.nzism.gcsb.govt.nz/ism-document/#1901 16.1.48.C.03.Control: System Classification(s): All Classifications; Compliance: SHOULD [CID:1901] `n" >> "$h.RegularChecks"
}

"=================================================================================================================" >> "$h.RegularChecks"

#Check for any Clear text Protocol Service running on the machine

$running_services=netstat -anob
netstat -anob | Select-String 0.0.0.0:80, 0.0.0.0:25, 0.0.0.0:20, 0.0.0.0:21, 0.0.0.0:110, 0.0.0.0:143 >> "$h.RegularChecks"
netstat -anob | Select-String 0.0.0.0 >> "$h.RegularChecks"
write-host("Checking for any Clear text Protocol Service running on the machine HTTP, SMTP, FTP, POP3, IMAPV4 `n" ) -ForegroundColor Green
"Review if any clear test protocol service is running on the machine" >> "$h.RegularChecks"


"=================================================================================================================" >> "$h.RegularChecks"
















