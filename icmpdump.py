#!/usr/bin/env python

from scapy.all import *
import threading
import time
import signal


# http://stackoverflow.com/questions/18994242/why-isnt-scapy-capturing-vlan-tag-information/18995865#18995865
# http://stackoverflow.com/questions/17314510/how-to-fix-scapy-warning-pcapy-api-does-not-permit-to-get-capure-file-descripto

# apt-get install python-pcapy
# apt-get install python-pypcap

conf.use_pcap = True
conf.verb=0

import scapy.arch.pcapdnet

#iface_name='eth5'
#iface_mac='00:02:a5:4e:53:dc'

iface_name='eth1'
#iface_mac='00:15:60:0c:41:ea'
#iface_vip=''

class Helper(object):
	def __init__(self):
		self.time1=0
		self.time2=0
	def set1(self, t1):
		self.time1=t1
		return self.time1
	def set2(self, t2):
		self.time2=t2
		return self.time2
	def get1(self):
		return self.time1
	def get2(self):
		return self.time2

h = Helper()
h.set1(time.time())
h.set2(time.time())

def udp_handler(pkt):
	ts=time.time()
	if Dot1Q in pkt:
		vlan=pkt[Dot1Q].vlan
	else:
		vlan='untagged'

	if IP in pkt:
		src=pkt[IP].src
		dst=pkt[IP].dst
	elif IPv6 in pkt:
		src=pkt[IPv6].src
		dst=pkt[IPv6].dst

	if UDP in pkt:
		print "{ts:10.6f} VLAN={vlan} IP: {src} -> {dst} UDP sport,dport={sport},{dport}".format(
						ts=ts, vlan=vlan, src=src, dst=dst, sport=pkt[UDP].sport, dport=pkt[UDP].dport)


def icmp_handler(pkt):
	global h
	ts=time.time()
	if Dot1Q in pkt:
		vlan=pkt[Dot1Q].vlan
	else:
		vlan='untagged'

	if IP in pkt:
		src=pkt[IP].src
		dst=pkt[IP].dst
	elif IPv6 in pkt:
		src=pkt[IPv6].src
		dst=pkt[IPv6].dst

	if ICMP in pkt:
		print "{ts:10.6f} VLAN={vlan} IP: {src} -> {dst} ICMP id,seq,type={id},{seq},{type}".format(
						ts=ts, vlan=vlan, src=src, dst=dst, type=pkt[ICMP].type, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
		if pkt[ICMP].type == 8:
			h.set1(time.time())
		if pkt[ICMP].type == 0:
			h.set2(time.time())

		deltaT=h.get2()-h.get1()
		if (deltaT >= 0):
			print "delta T = {dt}ms".format(dt=deltaT*1000)
			#print "%f" % (h.get2())
			#print "%f" % (h.get1())
			return


def arp_handler(pkt):
	if Dot1Q in pkt:
		vlan=pkt[Dot1Q].vlan
	else:
		vlan='untagged'

	if ARP in pkt:
		print "{ts:10.6f} VLAN={vlan} ARP: {src} -> {dst} ARP op,hwsrc,psrc,hwdst,pdst={type},{hwsrc},{psrc},{hwdst},{pdst}".format(
						ts=time.time(), vlan=vlan, src=pkt.src, dst=pkt.dst, type=pkt[ARP].op, hwsrc=pkt[ARP].hwsrc,
						psrc=pkt[ARP].psrc, hwdst=pkt[ARP].hwdst, pdst=pkt[ARP].pdst)


def main():

	if os.geteuid() != 0:
		print "root permissions needed or figure it out how to capture packets as non-root"
		sys.exit(1)

	print conf.L2listen

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

	t = threading.Thread(
				target=sniff,
				kwargs={'prn':udp_handler, 'filter':'udp', 'iface': iface_name, 'store':0 },
				name='UDP'
				)
	threads.append(t)

	for worker in threads:
		worker.daemon=True
		print "%s worker starting" % (worker.name)
		worker.start()


	try:
		while (42):
			#time.sleep(1)
			signal.pause()
	except KeyboardInterrupt:
		print "CTRL+C caught"
		for worker in threads:
			print "%s worker joining main thread" % (worker.name)
			worker.join(1)
		sys.exit(0)


if __name__ == '__main__':
	main()
