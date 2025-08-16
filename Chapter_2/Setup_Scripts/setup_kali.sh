#!/bin/bash

# Make sure running script as root

if [[ $EUID -ne 0 ]]; then

   echo "Run this script as root!" 

   exit 1

fi

# Install AutoRecon
git clone https://github.com/Tib3rius/AutoRecon
cd AutoRecon
pip3 install -r requirements.txt
cd /home/vagrant && ls && pwd

# Install dependencies then evilwinrm
gem install winrm winrm-fs stringio
git clone https://github.com/Hackplayers/evil-winrm.git
              
# Install Impacket using the commands:
git clone https://github.com/SecureAuthCorp/impacket.git
sudo apt install virtualenv -y 
virtualenv impacketpy3-venv
source impacketpy3-venv/bin/activate
cd impacket
pip3 install -r requirements.txt
pip3 install .
cd ~/impacketpy3-venv/bin
python3 GetNPUsers.py
              
# Install Powersploit
cd /home/vagrant
git clone https://github.com/PowerShellMafia/PowerSploit
      
# Install gobuster
apt-get install gobuster -y

# Install seclists
apt-get install seclists -y
      
# Install kerbrute
cd /home/vagrant
git clone https://github.com/TarlogicSecurity/kerbrute

# Install Bloodhound
pip install bloodhound 

# Install Covenant
cd /home/vagrant
git clone --recurse-submodules https://github.com/cobbr/Covenant

# Install Crackmapexec
apt-get install python3-pip -y
apt-get install python3-venv -y
apt install crackmapexec
