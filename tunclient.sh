#!/bin/bash
#./simpletun -i tun0 -c $1 -d
ip addr add 10.0.1.1/24 dev tun0
ip link set tun0 up
route add -net 10.0.0.0 netmask 255.255.255.0 dev tun0
echo "Client set."
