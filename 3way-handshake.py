#!/usr/bin/env python3

### PROPER WAY
#import socket
#s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.connect(('192.168.1.53',8444))

### SCAPY WAY
from scapy.all import *

### GENERATE SYN, WAIT FOR SYNACK, GENERATE ACK
for sport in [17777,27777,37777,47777,57777]:

        ip = IP(src="192.168.77.77", dst="192.168.7.77")
        SYN = TCP(sport=sport, dport=8444, flags='S', seq=7777)
        SYNACK = sr1(ip/SYN)

        my_ack = SYNACK.seq + 1
        ACK = TCP(sport=sport, dport=8444, flags='A', seq=7778, ack=my_ack)
        send(ip/ACK)

### RESPOND TO SYN PACKETS

#os.system("iptables -A OUTPUT -p tcp -o eth0 --sport 8444 --tcp-flags RST RST -j DROP")
#def packet(pkt):
#    if pkt[TCP].flags == 2:
#        print('SYN packet detected port : ' + str(pkt[TCP].sport) + ' from IP Src : ' + pkt[IP].src)
#        send(IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport,ack=pkt[TCP].seq + 1, flags='SA'))
#sniff(iface="eth0", prn=packet, filter="tcp[0xd]&18=2 and port 8444",count=100)
#os.system("iptables -D OUTPUT -p tcp -o eth0 --sport 8444 --tcp-flags RST RST -j DROP")


### SEND PAYLOAD
#payload = "stuff"
#PUSH = TCP(sport=1050, dport=8444, flags='PA', seq=11, ack=my_ack)
#send(ip/PUSH/payload)
