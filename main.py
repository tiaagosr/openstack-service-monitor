import imports
from scapy.all import *
from protocols import amqp
from modules.linkusage import start_link_metering

#[IP][TCP][Raw]

#SNIFF_FILTER = "tcp port 1052"

start_link_metering(interval=10, iface='wlp2s0', filter='udp')