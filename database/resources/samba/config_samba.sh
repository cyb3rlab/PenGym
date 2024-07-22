#!/bin/bash

samba_path=$1

echo "--Start the samba service"
cd  ${samba_path}
./configure
sudo make
sudo make install

echo "--Move config file"
sudo cp smb.conf /usr/local/samba/etc
sudo chown root:root /usr/local/samba/etc/smb.conf
sudo chmod 644 /usr/local/samba/etc/smb.conf

sudo mkdir /var/lib/samba

echo "--Create shared file"
sudo mkdir /home/shared
sudo chmod 777 /home/shared

