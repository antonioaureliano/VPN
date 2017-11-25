#!/bin/bash
#./simpletun -i tun0 -s -d
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 up
route add -net 10.0.1.0 netmask 255.255.255.0 dev tun0
echo "Server set."
