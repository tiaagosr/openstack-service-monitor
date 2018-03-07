from scapy.all import IP, Packet, sniff, TCP
from threading import Thread, Timer, Event
from database import *

METERING_INTERVAL = 10
SNIFF_INTERFACE = 'wlp2s0'
SNIFF_FILTER = 'tcp'

metering_buffer = {'etc' : 0, 'nova': 0, 'keystone': 0, 'swift': 0, 'glance': 0, 'cinder': 0}
ignored_packets = 0
port_range = {'nova': set([5900, 6080, 6081, 6082, 8773, 8774, 8775] + list(range(5900, 5999))), 
              'keystone': set([5000, 35357]), 
              'swift': set([873, 6000, 6001, 6002, 8080]), 
              'glance': set([9191, 9292]),
              'cinder': set([3260, 8776])}

def set_metering_interval(value):
    global METERING_INTERVAL
    METERING_INTERVAL = int(value)

def set_interface(value):
    global SNIFF_INTERFACE
    SNIFF_INTERFACE = value

def measure_packet(packet):
    if TCP in packet:
        global metering_buffer
        port_dst = packet[TCP].dport
        packet_class = classify_packet(port_dst)
        metering_buffer[packet_class] += packet[IP].len
    else:
        global ignored_packets
        ignored_packets += 1

def calculate_usage():
    global metering_buffer, ignored_packets
    for service in metering_buffer:
        metering_buffer[service] = metering_buffer[service] / METERING_INTERVAL
    store_metering_result(result=dict(metering_buffer), iface=SNIFF_INTERFACE, ignored_count=ignored_packets)
    for service in metering_buffer:
        metering_buffer[service] = 0
    ignored_packets = 0
    print_results()

class LinkMetering(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.stopped = Event()

    def run(self):
        while not self.stopped.wait(METERING_INTERVAL):
            calculate_usage()

    def stop_execution(self):
        self.stopped.set()

def classify_packet(port):
    for service in port_range:
            if port in port_range[service]:
                return service
    return 'etc'

def start_link_metering(interval=METERING_INTERVAL, iface=SNIFF_INTERFACE, filter=SNIFF_FILTER, sqli_path=DBSession.sqli_path):
    set_metering_interval(interval)
    set_interface(iface)
    DBSession.sqli_path = sqli_path
    print("Metering link usage, interval: "+str(interval))
    metering_sniff = Thread(target=sniff, kwargs={'iface':iface, 'prn':measure_packet, 'filter':filter})
    metering_sniff.start()
    link_metering = LinkMetering()
    link_metering.start()