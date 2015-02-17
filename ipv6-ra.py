#!/usr/bin/env python

from scapy.all import *

ipv6=IPv6()
ipv6.dst='ff02::1'
ra=ICMPv6ND_RA()
raopt=ICMPv6NDOptSrcLLAddr()
raopt.lladdr='24:a4:3c:b3:4d:cd'
raprefix=ICMPv6NDOptPrefixInfo()
raprefix.prefixlen=64
raprefix.prefix='2001:db8:f1f0:23ff::'
raprefix.preferredlifetime=0
raprefix.validlifetime=0
send(ipv6/ra/raopt/raprefix,iface='eth1')

