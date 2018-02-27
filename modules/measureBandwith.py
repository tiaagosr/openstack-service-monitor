from scapy.all import *
from threading import Thread, Timer, Event
from database import *

INTERVAL = 5
trafficBuffer = 0

SNIFF_INTERFACE = "wlp2s0"
SNIFF_FILTER = "tcp"

def countTraffic(pkt):
    if IP in pkt:
        global trafficBuffer
        trafficBuffer += pkt[IP].len

def printAvg(interval):
    global trafficBuffer
    measurement = int(trafficBuffer/interval)
    storeMeasurement(measurement, SNIFF_INTERFACE)
    trafficBuffer = 0

class MeasurementPersistence(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.stopped = Event()

    def run(self):
        while not self.stopped.wait(INTERVAL):
            printAvg(INTERVAL)
            
            

    def stopExecution(self):
        self.stopped.set()

thread = MeasurementPersistence()
thread.start()