#!/bin/sh
echo "--Install dependencies"
sudo apt-get update
wait
sudo apt-get install -y python
wait