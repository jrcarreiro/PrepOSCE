#!/usr/bin/env python

import sys
from scapy.all import sr1,IP,ICMP

packet=sr1(IP(dst=sys.argv[1])/ICMP())
if packet:
    packet.show()