#!/bin/sh
echo "--Install dependencies"
sudo apt-get update
wait
sudo apt-get install -y build-essential make libssl-dev
wait