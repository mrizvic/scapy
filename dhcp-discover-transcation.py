#!/usr/bin/env python

from scapy.all import *

conf.checkIPaddr=False
localiface = 'eth1'
requestMAC = 'fc:4d:d4:33:2f:41'
myhostname='sundancer'
localmac = get_if_hwaddr(localiface)
localmacraw = requestMAC.replace(':','').decode('hex')


dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover'), 'end'])

print dhcp_discover.display()

dhcp_offer = srp1(dhcp_discover,iface=localiface)

print dhcp_offer.display()

myip=dhcp_offer[BOOTP].yiaddr
sip=dhcp_offer[BOOTP].siaddr
xid=dhcp_offer[BOOTP].xid

dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=xid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])

print dhcp_request.display()

dhcp_ack = srp1(dhcp_request,iface=localiface)

print dhcp_ack.display()
