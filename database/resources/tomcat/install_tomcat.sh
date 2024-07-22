#!/bin/sh
echo "--Install Tomcat"
sudo apt-get update
wait
sudo apt-get install -y default-jdk tomcat9
wait