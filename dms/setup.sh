#!/bin/bash
DMS=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
sed -i  "s/10.0.0.19/${DMS}/" ~/i2nsf-dms/dms-server/confd.conf

sudo apt update
sudo apt install mysql-server make

python3 -m pip install mysql-connector-python paramiko configparser 
