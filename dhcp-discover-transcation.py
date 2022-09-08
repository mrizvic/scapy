#!/usr/bin/env python

from scapy.all import *

conf.checkIPaddr=False

def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

# configuration
localiface = 'eth1'
requestMAC = 'fc:4d:d4:33:2f:41'
myhostname='vektor'
localmac = get_if_hwaddr(localiface)
#localmacraw = requestMAC.replace(':','').decode('hex')
localmacraw = mac_to_bytes(requestMAC)

# craft DHCP DISCOVER
dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover'), 'end'])
print dhcp_discover.display()

# send discover, wait for reply
dhcp_offer = srp1(dhcp_discover,iface=localiface)
print dhcp_offer.display()

# craft DHCP REQUEST from DHCP OFFER
myip=dhcp_offer[BOOTP].yiaddr
sip=dhcp_offer[BOOTP].siaddr
xid=dhcp_offer[BOOTP].xid
dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=xid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
print dhcp_request.display()

# send request, wait for ack
dhcp_ack = srp1(dhcp_request,iface=localiface)
print dhcp_ack.display()
