#!/bin/bash

smtp_path=$1

echo "--Start the smtp service"
cd  ${smtp_path}
./configure
sudo make
sudo make install

echo "--Move config file"
sudo cp smtpd.conf /usr/local/etc/

sudo mkdir /etc/mail
sudo cp aliases /etc/mail

echo "--Create opensmtpd user"
mkdir /var/empty
useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd
useradd -c "SMTPD Queue" -d /var/empty -s /sbin/nologin _smtpq