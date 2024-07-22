#!bin/sh

apache_path=$1
cd ${apache_path}
sudo ./configure
wait
sudo make
wait
sudo make install
wait
cp ${apache_path}/httpd.conf /usr/local/apache2/conf

wait