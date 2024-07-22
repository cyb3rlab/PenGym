#!/bin/sh

echo "--Start smtp"
sudo /usr/local/sbin/smtpd &
wait