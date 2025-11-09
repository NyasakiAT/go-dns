#!/bin/bash
clear
echo "GO-DNS"
dnsperf -s 192.168.1.11 -d /home/nyasaki/Downloads/queryfile-example-10million-201202_part01 -c 10 -l 60 -Q 1000 | grep "Queries per second"
echo "Firewall"
dnsperf -s 192.168.1.1 -d /home/nyasaki/Downloads/queryfile-example-10million-201202_part01 -c 10 -l 60 -Q 1000 | grep "Queries per second"
