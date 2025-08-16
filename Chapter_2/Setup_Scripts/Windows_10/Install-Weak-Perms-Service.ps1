Set-MpPreference -DisableRealtimeMonitoring $true

sc.exe create "vulnservice2" binPath="C:\Program Files\VulnService\Vuln Service 5.6\vs.exe" start=auto DisplayName="Vuln Service 2"

# Get SID value, put where $sidVALUE is in next command
echo "find SID value in the output of whoami /user and plug it into the next command with sc.exe ..."
whoami /user

# set security permissions for service
sc.exe sdset vulnservice2 "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sidVALUE)"
