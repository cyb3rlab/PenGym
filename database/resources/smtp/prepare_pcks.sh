#!/bin/bash
echo "--Install dependencies"
sudo apt-get update
wait
sudo apt-get install -y build-essential make build-essential libssl-dev libasr-dev libevent-dev zlib1g-dev bison automake-1.15 libtool
wait
#new autoconf2.69