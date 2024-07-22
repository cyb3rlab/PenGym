#!/bin/sh

echo "--Start samba"
sudo /usr/local/samba/sbin/smbd &
wait
