import imports
from scapy.all import *
from protocols import amqp
from modules.measureBandwith import *

#[IP][TCP][Raw]

#SNIFF_FILTER = "tcp port 1052"
SNIFF_INTERFACE = "wlp2s0"

SNIFF_FILTER = ""

def arp_display(pkt):
    return pkt.summary()
 
sniff(iface=SNIFF_INTERFACE, prn=countTraffic, filter=SNIFF_FILTER)
