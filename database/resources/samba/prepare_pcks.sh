#!/bin/sh
echo "--Install dependencies"
sudo apt-get update
wait
sudo apt-get install -y build-essential make libacl1-dev libattr1-dev libblkid-dev libgnutls28-dev libreadline-dev python python2-dev python-dnspython libpopt-dev libldap2-dev libbsd-dev libcups2-dev dnsutils attr docbook-xsl pkg-config libssl-dev libusb-1.0-0-dev libgtk-3-dev
wait