#!/bin/bash
#-----NETWORK TRIGGERS SCRIPT-----
#set timer to wait between commands, 600 = 10 minutes
timer=600
#Internal Port Scanner (SCA) - Device has started a port scan on a device internal to your network.
nmap 192.168.1.0/24
sleep $timer
#ICMP Abuse (SCA) - Device has been sending unusually large ICMP packets to a new external server.
sudo hping3 --icmp 17.253.7.206 -d 600 -c 101 --faster
sleep $timer
#New IP Scanner (SCA) - Device started scanning the local IP network.
nmap 192.168.0.0/24
sleep $timer
#New SNMP Sweep (SCA) - Device attempted to reach a large number of hosts using SNMP.
nmap -sT -p 161 -Pn 192.168.1.0/24
sleep $timer
#Confirmed Threat Watchlist Hit (SCA) - Device interacted with an external resource that is associated with a known threat.
nmap 198.51.100.100
sleep $timer
#SMB Connection Spike (SCA) - Device attempted to contact an unusually large number of SMB servers.
nmap -sT -p 445 -v -Pn 192.168.1.0/24
sleep $timer
#New Unusual DNS Resolver (SCA) - Device contacted a DNS resolver that it doesn't normally use.
nslookup cisco.com 75.75.75.75
sleep 30
nslookup cisco.com 185.49.140.63
sleep 30
nslookup cisco.com 8.8.8.8
sleep $timer
#DNS Abuse (SCA) - Device has been sending unusually large DNS packets.
nping --udp -p 53 75.75.75.75 --data-length 1200 -c 10000 --rate 40
sleep 30
nping --udp -p 53 64.102.6.247 --data-length 1200 -c 10000 --rate 40
sleep $timer
#Outbound SMB Connection Spike (SCA) - Device is communicating with a large number of external hosts using SMB ports.
nmap -sT -p 445 -v -Pn 17.0.0.0/31
sleep $timer
#LDAP Connection Spike (SCA) - Device attempted to contact an unusually large number of internal LDAP servers.
nmap -sT -p 389 -Pn 192.168.3.0/24
sleep $timer
#NetBIOS Connection Spike (SCA) - Device attempted to contact large number of hosts using NetBIOS.
nmap -sT -p 139 -Pn 192.168.4.0/24 