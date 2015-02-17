#!/usr/bin/env python

from scapy.all import *

conf.checkIPaddr=False
localiface = 'eth1'
requestMAC = 'fc:4d:d4:33:2f:41'
requestMACraw = requestMAC.replace(':','').decode('hex')
releaseIP='192.168.179.113'
serverIP='192.168.179.5'
localmac = get_if_hwaddr(localiface)
foo,localmacraw = get_if_raw_hwaddr(localiface)

dhcp_release = IP(dst=serverIP)/UDP(sport=68,dport=67)/BOOTP(chaddr=requestMACraw, ciaddr=releaseIP, xid=RandInt())/DHCP(options=[('message-type','release'), 'end'])

send(dhcp_release)
