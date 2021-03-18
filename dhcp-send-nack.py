#!/usr/bin/python2

# This code was used in 2021 to force stuck clients requesting IP address
# from old dhcp server which was no longer in use. Clients were behind relay
# agent and because isc-dhcpd server was sending NAK's to broadcast address
# I need to hack something.
# This code is quick and dirty modify of https://github.com/david415/dhcptakeover

import sys
from scapy.all import DHCP, ARP, BOOTP, Ether, UDP, IP, sendp, sniff

class DHCPSendNack:

    def __init__(self, mac='', ip='', nak_limit=3):

        self.dhcp_srv_mac  = "00:11:22:aa:bb:cc"
        self.dhcp_srv_ip   = "1.2.3.4"
        self.gateway_mac   = "00:aa:bb:00:11:22"
        self.nak_limit     = 3

    def send_nack(self, packet):
        print("### INCOMING PACKET FROM: ", packet[IP].src)
        #packet.show()
        if packet[IP].dst == self.dhcp_srv_ip and DHCP in packet:
            nak = Ether(src=self.dhcp_srv_mac, dst=self.gateway_mac) / \
                IP(src=self.dhcp_srv_ip, dst=packet[BOOTP].ciaddr) / \
                UDP(sport=67,dport=68) / \
                BOOTP(op=2, ciaddr=packet[BOOTP].ciaddr, siaddr=self.dhcp_srv_ip, chaddr=packet[BOOTP].chaddr, xid=packet[BOOTP].xid) / \
                DHCP(options=[('server_id', self.dhcp_srv_ip),('message-type','nak'), ('end')])

            print("### OUTGOING NAK TO: ", nak[IP].dst)
            #nak.show()
            sendp(nak, iface="ens224")

    def run(self):
        sniff(iface=["ens224"], filter="dst host 1.2.3.4 and (port 67 or 68)", prn=self.send_nack, store=0)

def main():

    d = DHCPSendNack()
    d.run()

if __name__ == '__main__':
    sys.exit(main())
