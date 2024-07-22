#!/bin/bash

proftpd_path=$1
hostname=$2

echo "--Setup the ProFTPD service"
cd ${proftpd_path}
./configure
wait
sudo make
wait
sudo make install
wait

# Move new config file
sudo mv proftpd.conf /usr/local/etc/

# update host name
sudo sed -i "s/ubuntubase/${hostname}/g" /etc/hosts

