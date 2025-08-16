#!/bin/bash

# Make sure running script as root

if [[ $EUID -ne 0 ]]; then

   echo "Run this script as root!" 

   exit 1

fi

apt install curl -y &> /dev/null
apt install gcc -y &> /dev/null
groupadd admins &> /dev/null
groupadd reserved &> /dev/null

useradd -m -s /bin/bash -p $(openssl passwd -1 "password") bobjones &> /dev/null
useradd -m -s /bin/bash -p $(openssl passwd -1 "Password1") dillon &> /dev/null
useradd -m -s /bin/bash -p $(openssl passwd -1 "Secret1") kennyp &> /dev/null
useradd -m -s /bin/bash -p $(openssl passwd -1 "Password123") cynthia &> /dev/null
useradd -m -s /bin/bash -p $(openssl passwd -1 "Robrules21") robbyg &> /dev/null
useradd -m -s /bin/bash -p $(openssl passwd -1 "Ilovesports123") bucko &> /dev/null

if grep -Fxq "beh ALL=(ALL) /usr/bin/python3 *" /etc/sudoers
then
    echo "there already" &> /dev/null
else
    echo "beh ALL=(ALL) /usr/bin/python3 *" >> /etc/sudoers 
fi

if grep -Fxq "robbyg ALL=(ALL) /usr/bin/man" /etc/sudoers

then

    echo "there already" &> /dev/null

else

    echo "robbyg ALL=(ALL) /usr/bin/man" >> /etc/sudoers

fi


if grep -Fxq "kennyp ALL=(ALL) NOPASSWD:/usr/bin/vi" /etc/sudoers

then 

   echo "there already" &> /dev/null

else 

    echo "kennyp ALL=(ALL) NOPASSWD:/usr/bin/vi" >> /etc/sudoers

fi



if grep -Fxq "dillon ALL=(ALL) NOPASSWD:/bin/nano" /etc/sudoers

then 

   echo "there already" &> /dev/null

else 

   echo "dillon ALL=(ALL) NOPASSWD:/bin/nano" >> /etc/sudoers

fi


# Install MySQL server

export DEBIAN_FRONTEND="noninteractive"

debconf-set-selections <<< "mysql-server mysql-server/root_password password root"

debconf-set-selections <<< "mysql-server mysql-server/root_password_again password root"

apt-get update -y &> /dev/null

apt-get install -y mysql-server &> /dev/null

echo '[mysqld] skip-grant-tables' >> /etc/mysql/my.cnf


# Install SUID bin

echo "#include <unistd.h>" > /usr/bin/rootme.c

echo "int main()" >> /usr/bin/rootme.c

echo "{" >> /usr/bin/rootme.c

echo "setuid(0);" >> /usr/bin/rootme.c

echo "execl("'"/bin/sh"'","'"/bin/bash"'", NULL);" >> /usr/bin/rootme.c

echo "return 0;" >> /usr/bin/rootme.c

echo "}" >> /usr/bin/rootme.c

# Compile the binary

gcc /usr/bin/rootme.c -o /usr/bin/rootme
chgrp reserved /usr/bin/rootme
chmod g+x /usr/bin/rootme
chmod o-rwx /usr/bin/rootme
chmod +s /usr/bin/rootme

cp /usr/bin/rootme /home/cynthia/cp
chown root:reserved /home/cynthia/cp

# Make vulnerable cron job Bash script
touch /home/beh/levelup.sh

chmod +x /home/beh/levelup.sh

chmod u=rwx,g=rwx,o=rw /home/beh/levelup.sh

chown root.reserved /home/beh/levelup.sh

setfacl -m u:bobjones:rw /etc/passwd

usermod -a -G admins kennyp

usermod -aG reserved cynthia

# Install SUID bin 2

echo "#include <unistd.h>" > /home/bobjones/cp.c

echo "int main()" >> /home/bobjones/cp.c

echo "{" >> /home/bobjones/cp.c

echo "setuid(0);" >> /home/bobjones/cp.c

echo "execl("'"/bin/sh"'","'"/bin/bash"'", NULL);" >> /home/bobjones/cp.c

echo "return 0;" >> /home/bobjones/cp.c

echo "}" >> /home/bobjones/cp.c

# Compile the binary

gcc /home/bobjones/cp.c -o /home/bobjones/cp

chmod +sx /home/bobjones/cp

# Install vulnserver

apt install wine-stable -y &> /dev/null

apt install git -y &> /dev/null

git clone https://github.com/stephenbradshaw/vulnserver

cd vulnserver

chmod +x vulnserver.exe

# Install Docker

apt install docker.io -y

usermod -aG docker $USER

usermod -aG docker beh

systemctl enable docker

docker pull wordpress:latest

docker pull mysql:latest

docker run --name standalonemysql -e MYSQL_ROOT_PASSWORD=root -e WORDPRESS_DB_USER=root -d mysql 

docker run --name wordpress -p 80:80 -d wordpress

docker network create --attachable hackpress-net

docker network connect hackpress-net wordpress

docker network connect hackpress-net standalonemysql

docker exec -it standalonemysql bash -c "mysql -uroot -proot -e "'"CREATE DATABASE wordpress; exit;"'"" &> /dev/null

docker exec -it standalonemysql bash -c "mysql -uroot -proot -e 'USE wordpress; CREATE TABLE credentials(username VARCHAR(20), password VARCHAR(41)); exit;'" &> /dev/null

docker exec -it standalonemysql bash -c "mysql -uroot -proot -e 'USE wordpress; INSERT INTO credentials(username, password) VALUES ("'"cynthia"'","'"Password123"'");exit;'" &> /dev/null

# Install drupalgeddon 

docker run --name drupal_mysql -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=drupal -e MYSQL_USER=drupal -e MYSQL_PASSWORD=pass -d mysql:5.5

docker run --name drupal-site -p 9006:80 --link drupal_mysql:mysql -d drupal:8.5.0

# Set all containers to restart unless told not to

docker update --restart unless-stopped $(docker ps -q)


# Make RSA keypairs

mkdir -p /home/dillon/.ssh

ssh-keygen -b 4096 -N 'Password1' -f /home/dillon/.ssh/id_rsa

cat /home/dillon/.ssh/id_rsa.pub >> /home/dillon/.ssh/authorized_keys

mkdir -p /home/bobjones/.ssh

ssh-keygen -b 4096 -N 'Password1' -f /home/bobjones/.ssh/id_rsa

cat /home/bobjones/.ssh/id_rsa.pub >> /home/bobjones/.ssh/authorized_keys

# Set rbash user

usermod -s /bin/rbash bucko

echo "sorry dillon use this new rsa key to connect remotely from now on, have fun!" >> /nfs_srv/note.txt

cat /home/dillon/.ssh/id_rsa >> /nfs_srv/note.txt

# Install ssh server

apt install openssh-server -y &> /dev/null

systemctl enable ssh

# Install NFS
apt install nfs-kernel-server -y 
systemctl enable nfs-kernel-server
mkdir /nfs_srv
chmod 777 /nfs_srv/
chown nobody:nogroup /nfs_srv/
echo "/nfs_srv 10.0.0.197(rw,sync,no_root_squash,no_subtree_check)" >> /etc/exports
exportfs -ra   
systemctl restart nfs-kernel-server

# Leave note
echo "sorry dillon use this new rsa key to connect remotely from now on, have fun!" >> /nfs_srv/note.txt

cat /home/dillon/.ssh/id_rsa >> /nfs_srv/note.txt

# Set vuln cronjob for root
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/beh/levelup.sh") | crontab -
