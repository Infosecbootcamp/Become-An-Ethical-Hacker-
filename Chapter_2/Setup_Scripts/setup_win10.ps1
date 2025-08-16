# Part 1
Write-Host "Make sure the network adapters are on for this VM first in this order: Internal, HostOnly, NAT"
 Read-Host "Press any key to confirm this is done..."

        $netConfig = Get-NetIPConfiguration

        $global:newintalias = "nothing"

        foreach($thing in $netConfig)

        {

        if ($thing.InterfaceDescription -Like "*Desktop Adapter") {

                $newintalias = $thing.InterfaceAlias

           }

        }

        # Get member with MT Desktop Adapter
        $eth = Get-NetIPConfiguration | where {$_.InterfaceAlias -eq 'ethernet'}
        New-NetIPAddress -IPAddress 10.0.0.64 -InterfaceAlias $eth.InterfaceAlias  -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 10.0.0.33
        Set-DnsClientServerAddress -InterfaceAlias $eth.InterfaceAlias  -ServerAddress 10.0.0.33
        Rename-Computer -NewName BEHWIN10

        Restart-Computer -Force

        if (Test-Connection -ComputerName 10.0.0.33 -Quiet) { 

        Write-Host "proceeding"

        } else { 

        Write-Host "configure and turn on BEHDC1(10.0.0.33) first!" 

        exit

        }

# Part 2
 # Turn off the firewall on the Public, Private, and Domain network profiles.

        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False

        # Turn on RDP

        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

        # Put Wdigest creds back in memory

        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -name "UseLogonCredential" -value 1

        # Turn on ANSI color bit

        REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1

        # Set the RDP NLA setting to Disabled

        (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:computername -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

        # Disable Defender

        Set-MpPreference -DisableRealtimeMonitoring $true

        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

        # Install PSCredential object file

        $User = "da-cynthia"

        $Pass = ConvertTo-SecureString -String "Password123" -AsPlainText -Force

$Credential = New-Object -TypeName System.Management.Automation.PSCredential `
-ArgumentList $User, $Pass

        $Credential | Export-Clixml -Path "C:\Users\Public\creds.xml"

        # Check

        $cred = Import-Clixml -Path "C:\Users\Public\creds.xml"

        $cred.GetNetworkCredential().Password
        
        #             Join to testlab.local domain              #


        $domain = "testlab"

        $password = "Hyperdrive1" | ConvertTo-SecureString -asPlainText -Force

        $username = "$domain\da-bobjones" 

        $credential = New-Object System.Management.Automation.PSCredential($username,$password)

        Add-Computer -DomainName $domain -Credential $credential
Restart-Computer -Force

# Part 3

# AV Now Gone Due To GPO
# Add user to rdp users 
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "bobjones"
# Vuln Service Unquoted Service Path
        New-Item -ItemType directory -Path "C:\Program Files\Fake Service\Fake Service 9.0"
        sc.exe create "vulnservice" binPath="C:\Program Files\Fake Service\Fake Service 9.0\Fake.exe" start=auto DisplayName="Fake Service"
        icacls.exe "C:\Program Files\Fake Service" /grant bobjones:rw
        # Vuln Service Weak Service Permissions 
        # Make dir
        if (Test-Path -Path "C:\Program Files\VulnService\Vuln Service 5.6") {
            Break
        } else {
        New-Item -ItemType directory -Path "C:\Program Files\VulnService\Vuln Service 5.6"
}
        # Install chocolatey
        Set-ExecutionPolicy Bypass -Scope Process -Force; iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex
        choco install sysinternals --params "/InstallDir:C:\Users\Public\sysinternals" -y --force
        choco install visualstudio2019community -y --force
        #                 Download Vulnserver                   #
$w="https://github.com/stephenbradshaw/vulnserver/blob/master/vulnserver.exe?raw=true"
Invoke-WebRequest -Uri $w -OutFile "C:\Users\Public\vulnserver.exe" | Out-Null
        $check = Get-FileHash -Algorithm MD5 "C:\Users\Public\vulnserver.exe" 
        if ($check.Hash -eq "C2DB1BCE2936D2F04370934091241D6A") {
        } else {
           Write-Host "hash not the same for vulnserver: vulnserver.exe!"
        }
$w2="https://github.com/stephenbradshaw/vulnserver/blob/master/essfunc.dll?raw=true"
Invoke-WebRequest -Uri $w2 -OutFile "C:\Users\Public\essfunc.dll" | Out-Null
        $check2 = Get-FileHash -Algorithm MD5 "C:\Users\Public\essfunc.dll"
        if ($check2.Hash -eq "4E47AEAC37BCCD2F5E635CCC20E2F5B8") {
        } else {
           Write-Host "hash not the same for vulnserver: essfunc.dll!"
        }
        ################# Install MySQL ###################
        # Install mysql
        choco install mysql -y | Out-Null
        # Connector/NET is a fully-managed ADO.NET driver for MySQL
$w3="https://dev.mysql.com/get/Downloads/Connector-Net/mysql-connector-net-8.0.26.msi"
Invoke-WebRequest -Uri $w3 -OutFile "C:\Users\Public\mysql-connector-net-8.0.26.msi" | Out-Null
        msiexec.exe  /I "C:\Users\Public\mysql-connector-net-8.0.26.msi" /quiet
        # Connect to the libaray MySQL.Data.dll
        Add-Type -Path 'C:\Program Files (x86)\MySQL\MySQL Connector Net 8.0.26\Assemblies\v4.5.2\MySql.Data.dll'
$Conn =[MySql.Data.MySqlClient.MySqlConnection]@{ConnectionString='server=127.0.0.1;uid=root;pwd=;database='}
        $Conn.Open()
        $sql = New-Object MySql.Data.MySqlClient.MySqlCommand
        $sql.Connection = $Conn
        $sql.CommandText = 'CREATE DATABASE vulnerable_stuff;'
        $sql.ExecuteNonQuery()
        $sql.CommandText =  'USE vulnerable_stuff;'
        $sql.ExecuteNonQuery()
        $sql.CommandText = 'CREATE TABLE credentials (username VARCHAR(20), password VARCHAR(41));'
        $sql.ExecuteNonQuery()
        $sql.CommandText ='INSERT INTO credentials (username, password) VALUES ("wa-travisb","70efa86d5b7f38a48368d2dc3c32c296");'
        $sql.ExecuteNonQuery()
        $sql.CommandText ="ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';"
        $sql.ExecuteNonQuery()
        $Conn.Close()
 Set-MpPreference -DisableRealtimeMonitoring $true
        # Add local admins
        Add-LocalGroupMember -Group "Administrators" -Member "testlab\wa-travisb"
        Add-LocalGroupMember -Group "Administrators" -Member "testlab\wa-kennyp"
      
        # Download mona
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/corelan/mona/master/mona.py" -OutFile "C:\Users\Public\mona.py"
        # Install python3
        choco install python3 -y | Out-Null; choco install pip3 -y | Out-Null;refreshenv | Out-Null
choco install dotnet3.5 -y
        # Restart for changes to take effect
        Restart-Computer -Force
