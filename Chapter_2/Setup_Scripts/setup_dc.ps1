# Part One: Set the networking settings
 
$netConfig = Get-NetIPConfiguration
 foreach($thing in $netConfig)
{      
if ($thing.InterfaceDescription -Like "*Desktop Adapter") {
$intalias = $thing.InterfaceAlias
      }

  }
New-NetIPAddress -IPAddress 10.0.0.33 -InterfaceAlias $intalias -AddressFamily IPv4 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias $intalias -ServerAddress 127.0.0.1
Rename-Computer -NewName BEHDC
Set-SmbServerConfiguration -RequireSecuritySignature $false
Restart-Computer -Force

# Part Two: Install Services

Import-Module ServerManager
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

$recoverypw = ConvertTo-SecureString "P@ssW0rD!" -AsPlainText -Force
Install-ADDSForest `
-DomainNetbiosName testlab `
-DomainName testlab.local `
-DomainMode "WinThreshold" `
-ForestMode "WinThreshold" `
-InstallDns -LogPath "C:\Windows\NTDS" `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword $recoverypw `
-DatabasePath "C:\Windows\NTDS" `
-NoRebootOnCompletion `
-Force

Install-WindowsFeature DHCP -IncludeManagementTools|fl
Restart-Computer -Force

# Part Three: Local configurations
# Go to Server Manager and finish "DHCP Configuration"
# Go to Server Manager and finish "promote to Domain Controller"
# Continue 

# Turn off firewalls
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

# Turn on RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

 # Turn on ANSI color bit
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

# Set the RDP NLA setting to Disabled
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:computername -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

# Turn on WinRM
Enable-PSRemoting -Force

# Make new SMB shares
New-Item "C:\Shares\PUBLIC" –type directory
New-SmbShare -Name PUBLIC -Path C:\Shares\PUBLIC -FullAccess Everyone

# Allow insecure SMB auth
$regpath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
New-Item $regpath -Force | Out-Null
Set-ItemProperty -Path $regpath -name "AllowInsecureGuestAuth" -value 1

# Allow null SMB sessions
$r='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
New-ItemProperty `
-Path $r `
-PropertyType 'MultiString' `
-Name 'NullSessionShares' `
-Value @('PUBLIC')

# Install Webserver & FTP
Install-WindowsFeature -name Web-Server -IncludeManagementTools
Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
Import-Module WebAdministration
$FTPSite = 'test'  
$FTPRootDir = 'C:\inetpub\wwwroot'  
$FTPPort = 21  
New-WebFtpSite -Name $FTPSite -Port $FTPPort -PhysicalPath $FTPRootDir -Force

# Enable basic authentication on the FTP site  
$FTPPath = "IIS:\Sites\$FTPSite"  
$BasicAuth = 'ftpServer.security.authentication.basicAuthentication.enabled'
$Auth='ftpServer.security.authentication.anonymousAuthentication.enabled'  
Set-ItemProperty -Path $FTPPath -Name $BasicAuth -Value $True  
Set-ItemProperty -Path $FTPPath -Name $Auth -Value $True
Set-ItemProperty -Path $FTPPath -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
Set-ItemProperty -Path $FTPPath -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" 
Set-ItemProperty -Path $FTPPath -Name ftpServer.userIsolation.mode -Value "None" 
Add-WebConfiguration "/system.ftpServer/security/authorization" -value @{accessType="Allow";roles="";permissions="Read,Write";users="*"} -PSPath "IIS:\" -location "test"
Restart-WebItem "IIS:\Sites\$FTPSite" -Verbose

$Acl = Get-Acl $FTPRootDir
$Perms = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Perms)
Set-Acl $FTPRootDir $Acl

# Part 3 Config AD Domain
Restart-Computer -Force

New-ADUser -Name "johnj" -GivenName "johnj" -SamAccountName "johnj" -AccountPassword (ConvertTo-SecureString "Player1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "johnj" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "johnj" -AllowReversiblePasswordEncryption $true

New-ADUser -Name "jimbob" -GivenName "jimbob" -SamAccountName "jimbob" -AccountPassword (ConvertTo-SecureString "Gosportsteam1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "jimbob" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "jimbob"

New-ADUser -Name "da-jimbob" -GivenName "jimbob" -SamAccountName "da-jimbob" -AccountPassword (ConvertTo-SecureString "Gosportsteam1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "da-jimbob" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "da-jimbob"

New-ADUser -Name "cynthia" -GivenName "cynthia" -SamAccountName "cynthia" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "cynthia" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "cynthia"

New-ADUser -Name "jackr" -GivenName "jackr" -SamAccountName "jackr" -AccountPassword (ConvertTo-SecureString "Ineedaraise99" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "jackr" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "jackr"

New-ADUser -Name "da-cynthia" -GivenName "da-cynthia" -SamAccountName "da-cynthia" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "da-cynthia" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "da-cynthia" 

New-ADUser -Name "wa-travisb" -GivenName "wa-travisb" -SamAccountName "wa-travisb" -AccountPassword (ConvertTo-SecureString "Qwerty2020" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "wa-travisb" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "wa-travisb" 

New-ADUser -Name "bobjones" -GivenName "bobjones" -SamAccountName "bobjones" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "bobjones" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "bobjones" 
  
New-ADUser -Name "da-bobjones" -GivenName "da-bobjones" -SamAccountName "da-bobjones" -AccountPassword (ConvertTo-SecureString "Hyperdrive1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "da-bobjones" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "da-bobjones"       

New-ADUser -Name "sa-robbyg" -GivenName "sa-robbyg" -SamAccountName "sa-robbyg" -AccountPassword (ConvertTo-SecureString "RobbyRules2020" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "sa-robbyg" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "sa-robbyg"

New-ADUser `
-Name "svc-legacyapp" `
-GivenName "svc-legacyapp" `
-SamAccountName "svc-legacyapp" `
-AccountPassword (ConvertTo-SecureString "Summer2020" -AsPlainText -Force) `
-ChangePasswordAtLogon $false `
-DisplayName "svc-legacyapp" `
-Enabled $true `
-PasswordNeverExpires $true `
-UserPrincipalName "svc-legacyapp" `
-ServicePrincipalNames "svc-legacyapp/behdc.testlab.local:1234/cn=svc-legacyapp,ou=Users,dc=testlab,dc=local" 

Get-ADUser -Identity "svc-legacyapp" | Set-ADAccountControl -DoesNotRequirePreAuth:$true

 New-ADUser `
-Name "svc-customapp" `
-GivenName "svc-customapp" `
-SamAccountName "svc-customapp" `
-AccountPassword (ConvertTo-SecureString "Fall2020" -AsPlainText -Force) `
-ChangePasswordAtLogon $false `
-DisplayName "svc-customapp" `
-Enabled $true `
-PasswordNeverExpires $true `
-UserPrincipalName "svc-customapp" `
-ServicePrincipalNames "svc-customapp/behdc.testlab.local:1234/cn=svc-customapp,ou=Users,dc=testlab,dc=local"

New-ADUser -Name "wa-kennyp" -GivenName "wa-kennyp" -SamAccountName "wa-kennyp" -AccountPassword (ConvertTo-SecureString "Secret1" -AsPlainText -Force) -ChangePasswordAtLogon $false -DisplayName "wa-kennyp" -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "wa-kennyp" 

New-ADGroup -Name "Workstation Admins" -SamAccountName WorkstationAdmins -GroupCategory Security -GroupScope Global -DisplayName "Workstation Administrators" -Path "CN=Users,DC=testlab,DC=local" -Description "Members of this group are Workstation Administrators"

New-ADGroup -Name "Server Admins" -SamAccountName ServerAdmins -GroupCategory Security -GroupScope Global -DisplayName "Server Administrators" -Path "CN=Users,DC=testlab,DC=local" -Description "Members of this group are Server Administrators"

Add-ADGroupMember -Identity WorkstationAdmins -Members "wa-kennyp"
Add-ADGroupMember -Identity WorkstationAdmins -Members "wa-travisb"
Add-ADGroupMember -Identity ServerAdmins -Members "sa-robbyg"
Add-ADGroupMember -Identity "Domain Admins" -Members "da-jimbob"
Add-ADGroupMember -Identity "Domain Admins" -Members "da-cynthia"
Add-ADGroupMember -Identity "Domain Admins" -Members "da-bobjones"

# Add local admin to server
net localgroup Administrators /add sa-robbyg 
