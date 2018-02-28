import imports
from scapy.all import *
from protocols import amqp
from modules.linkusage import start_link_metering

#[IP][TCP][Raw]

#SNIFF_FILTER = "tcp port 1052"
SNIFF_INTERFACE = "wlp2s0"

SNIFF_FILTER = ""

start_link_metering(10)