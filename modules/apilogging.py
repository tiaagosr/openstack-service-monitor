from scapy.all import *
from threading import Thread, Timer, Event
from database import *
from scapy_http.http import *

SNIFF_INTERFACE = 'wlp2s0'
SNIFF_INTERFACE = 'lo'
SNIFF_FILTER = 'tcp and (portrange 8773-8777 or port 5000 or port 9292 or port 80)'
SNIFF_FILTER = 'tcp port 8080'

def evaluate_packet(packet):
    if IP in packet:
        IP_layer = IP
    elif IPv6 in packet:
        IP_layer = IPv6
    else:
        return

    if packet.haslayer('HTTP') and packet.haslayer('Raw'):
        print(packet.summary())
        return packet[IP_layer][TCP][HTTP][Raw].load

def start_api_logging(iface=SNIFF_INTERFACE, filter=SNIFF_FILTER, sqli_path=DBSession.sqli_path):
    DBSession.sqli_path = sqli_path
    print("Logging API access")
    logging_sniff = Thread(target=sniff, kwargs={'iface':iface, 'prn':evaluate_packet, 'filter':filter, 'offline':'test/testApi.pcap'})
    logging_sniff.start()