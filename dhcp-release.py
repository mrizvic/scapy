#!/usr/bin/env python

from scapy.all import *

conf.checkIPaddr=False

#configuration
localiface = 'eth1'
releaseMAC = 'fc:4d:d4:33:2f:41'
releaseIP='192.168.179.113'
serverIP='192.168.179.5'
releaseMACraw = releaseMAC.replace(':','').decode('hex')

#craft and send DHCP RELEASE 
dhcp_release = IP(dst=serverIP)/UDP(sport=68,dport=67)/BOOTP(chaddr=releaseMACraw, ciaddr=releaseIP, xid=RandInt())/DHCP(options=[('message-type','release'), 'end'])
send(dhcp_release)
