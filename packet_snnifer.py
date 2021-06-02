#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	print("sniffing ....")
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		print(packet.show())
		#url = packet[http.HTTPRequest].Host  + packet[http.HTTPRequest].Path
		url = packet[http.HTTPRequest].Referer
		#print(url)
		'''
		if packet.haslayer(scapy.Raw):
			
			load = packet[scapy.Raw].load
			keywords = ["usr","uname","username","email","pass","password","login","submit"]
			fo r keyword in keywords:
				if keyword in keywords:
					print(load.replace(b'&', b' - '))
					break
		'''

sniff("eth0")