#!/usr/bin/env python3

NGAP_PORT = 38412

import sys
from scapy.all import *
from scapy.utils import rdpcap

MAX_SEND = 15
send_count = 0

pkts=rdpcap("{}.pcap".format(sys.argv[1]))  # could be used like this rdpcap("filename",500) fetches first 500 pkts
for pkt in pkts:
    if SCTP not in pkt:
        # print ("This is not an SCTPs pkt!")
        continue
    if pkt[SCTP].sport != NGAP_PORT and pkt[SCTP].dport != NGAP_PORT:
        print ("This is a non-NGAP SCTP pkt! {} -> {}".format(pkt[SCTP].sport, pkt[SCTP].dport))
        print(pkt[SCTP].sport != NGAP_PORT, pkt[SCTP].dport != NGAP_PORT)
        continue
    print(pkt.summary())
    pkt[Ether].src= "00:04:00:00:00:00"  # i.e new_src_mac="00:11:22:33:44:55"
    pkt[Ether].dst= "00:aa:bb:00:00:01"
    pkt[IP].src= "10.0.0.10" # i.e new_src_ip="255.255.255.255"
    pkt[IP].dst= "10.0.1.10"
    sendp(pkt)
    send_count += 1
    if send_count == MAX_SEND:
        break
