from scapy.all import IP, Packet, sniff
from threading import Thread, Timer, Event
from database import *

METERING_INTERVAL = 10
SNIFF_INTERFACE = 'wlp2s0'
SNIFF_FILTER = 'tcp'

metering_buffer, ignored_packets = 0, 0

def set_metering_interval(value):
    global METERING_INTERVAL
    METERING_INTERVAL = int(value)

def measure_packet(packet):
    if IP in packet:
        global metering_buffer
        metering_buffer += packet[IP].len
    else:
        global ignored_packets
        ignored_packets += 1

def calculate_usage():
    global metering_buffer, ignored_packets
    result = int(metering_buffer / METERING_INTERVAL)
    store_result(result=result, iface=SNIFF_INTERFACE, ignored_count=ignored_packets)
    metering_buffer, ignored_packets = 0, 0
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


def start_link_metering(interval=METERING_INTERVAL, iface=SNIFF_INTERFACE, filter=SNIFF_FILTER, sqli_path=DBSession.sqli_path):
    if interval != METERING_INTERVAL:
        set_metering_interval(interval)
    DBSession.sqli_path = sqli_path
    print("Metering link usage, interval: "+str(interval))
    metering_sniff = Thread(target=sniff, kwargs={'iface':iface, 'prn':measure_packet, 'filter':filter})
    metering_sniff.start()
    link_metering = LinkMetering()
    link_metering.start()