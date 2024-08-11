#!/bin/bash

vsftpd_path=$1

echo "--Setup the vsftpd service"
cd ${vsftpd_path}
sudo make
wait
sudo useradd nobody
sudo mkdir /usr/share/empty

echo "--Anonymous FTP setup"
sudo mkdir /var/ftp/
sudo useradd -d /var/ftp ftp
sudo chown root.root /var/ftp
sudo chmod og-w /var/ftp

echo "--Copy vsftpd config file"
sudo cp vsftpd /usr/local/sbin/vsftpd
sudo cp vsftpd.conf.5 /usr/local/man/man5
sudo cp vsftpd.8 /usr/local/man/man8
sudo cp vsftpd.conf /etc

