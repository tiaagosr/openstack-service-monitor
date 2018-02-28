from scapy.all import *
from threading import Thread, Timer, Event
from database import *

METERING_INTERVAL = 10
SNIFF_INTERFACE = "wlp2s0"
SNIFF_FILTER = "tcp"

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
    store_result(result=result, interface=SNIFF_INTERFACE, ignored_count=ignored_packets)
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


def start_link_metering(interval=10):
    if interval != METERING_INTERVAL:
        set_metering_interval(interval)
    print("executing, interval: "+str(interval))

    metering_sniff = Thread(target=sniff, kwargs={"iface":SNIFF_INTERFACE, "prn":measure_packet, "filter":SNIFF_FILTER})
    metering_sniff.start()
    
    link_metering = LinkMetering()
    link_metering.start()