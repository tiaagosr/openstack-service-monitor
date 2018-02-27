from scapy.all import Packet

SNIFF_FILTER = "tcp port 5672"
SNIFF_INTERFACE = "br-flat-lan-1"

class Amqp(Packet):
    name = "Advanced Message Queueing Protocol"
    fields_desc = []