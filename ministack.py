#!/usr/bin/env python

from scapy.all import *
import threading
import time
import signal

iface_name='eth5'
iface_mac='00:02:a5:4e:53:dc'

conf.verb=0

def icmp_handler(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		reply=Ether()/IP()/ICMP()
		reply.dst			=pkt.src
		reply.src			=iface_mac
		reply[IP].src			=pkt[IP].dst
		reply[IP].dst			=pkt[IP].src
		reply[IP].id			=pkt[IP].id
		reply[ICMP].id			=pkt[ICMP].id
		reply[ICMP].seq			=pkt[ICMP].seq
		reply[ICMP]			=pkt[ICMP]	#copy original ICMP header to reply
		reply[ICMP].type		=0		#but convert type to echo-reply
		sendp(reply,iface=iface_name)


def arp_handler(pkt):
	if ARP in pkt and pkt[ARP].op == 1:			#if ARP and who-has
		reply=Ether()/ARP()
		reply.dst			=pkt.src
		reply.src			=iface_mac
		reply.type			=0x806
		reply.hwtype			=0x1
		reply.ptype			=0x800
		reply.hwlen			=6
		reply.plen			=4
		reply.op			=2		#is-at
		reply.hwsrc			=iface_mac
		reply.hwdst			=pkt.hwsrc
		reply.psrc			=pkt.pdst
		reply.pdst			=pkt.psrc
		sendp(reply,iface=iface_name)

def main():

	threads=[]

	t = threading.Thread(
				target=sniff,
				kwargs={'prn':arp_handler, 'filter':'arp', 'iface': iface_name, 'store': 0},
				name='ARP'
				)
	threads.append(t)

	t = threading.Thread(
				target=sniff,
				kwargs={'prn':icmp_handler, 'filter':'icmp', 'iface': iface_name, 'store': 0},
				name='ICMP'
				)
	threads.append(t)

	for worker in threads:
		worker.daemon=True
		print "%s worker starting" % (worker.name)
		worker.start()


	try:
		while (42):
			time.sleep(1)
			signal.pause()
	except KeyboardInterrupt:
		print "CTRL+C caught"
		for worker in threads:
			print "%s worker joining main thread" % (worker.name)
			worker.join(1)
		sys.exit(0)


if __name__ == '__main__':
	main()
