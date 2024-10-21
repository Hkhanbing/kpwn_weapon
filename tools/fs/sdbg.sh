#!/bin/sh
rm ./exp
wget http://192.168.3.241:9999/exp
chmod +x ./exp
lsmod
echo "wating for debug..."
