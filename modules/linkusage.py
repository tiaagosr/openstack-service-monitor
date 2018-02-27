from scapy.all import *
from threading import Thread, Timer, Event
from database import *

METERING_INTERVAL = 5
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
    storeResult(result, SNIFF_INTERFACE, ignored_packets)
    metering_buffer, ignored_packets = 0, 0

class LinkMetering(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.stopped = Event()

    def run(self):
        while not self.stopped.wait(METERING_INTERVAL):
            calculate_usage()
              

    def stopExecution(self):
        self.stopped.set()

link_metering = LinkMetering()
link_metering.start()