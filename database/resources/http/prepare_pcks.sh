#!/bin/sh
echo "--Install dependencies"
sudo apt-get update
wait
sudo apt-get install -y build-essential make bison flex libssl-dev libapr1 libapr1-dev libaprutil1 libaprutil1-dev libpcre3-dev
exit