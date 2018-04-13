from threading import Thread, Event
from peewee import SqliteDatabase
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Packet, TCP, IP, IPv6
from queue import Queue
import os
import time


class SniffThread(Thread):

    INSTANCE = None

    @staticmethod
    def instance(iface='', filter=''):
        if SniffThread.INSTANCE is None:
            SniffThread.INSTANCE = SniffThread(iface=iface, filter=filter)
        return SniffThread.INSTANCE

    def __init__(self, filter='', iface=''):
        super().__init__(name="osm-sniffer")
        self.queue = []
        self.stopped = None
        self.filter = filter
        self.iface = iface
        self.INSTANCE = self

    def start_sniffing(self, shared_queue: Queue, stop_event: Event, duration=-1) -> bool:
        self.queue.append(shared_queue)
        if self.stopped is None:
            self.stopped = stop_event
            self.start()
            return True
        return False

    def loop_sniff(self):
        while not self.stopped.is_set():
            if not self.queue[0].full():
                data = sniff(iface=self.iface, filter=self.filter, count=1000)
                for item in data:
                    for q in self.queue:
                        q.put(item)
            else:
                # Reduce CPU % Usage
                time.sleep(0.001)
        print("Producer Thread Stopped!")


    def store_packet(self, packet):
        if not self.queue[0].full():
            self.queue[0].put(packet)

    def run(self):
        self.loop_sniff()
        #sniff(iface=self.iface, filter='tcp', store=0, prn=self.store_packet)


class MonitoringModule(Thread):
    MODE_IPV4 = 'inet'
    MODE_IPV6 = 'inet6'
    TRAFFIC_OUTBOUND = 'out'
    TRAFFIC_INBOUND = 'in'
    QUEUE_SIZE = 10000
    START_TIME = time.time()
    DATABASE = SqliteDatabase(None)

    def __init__(self, interface='lo', filter='', mode=MODE_IPV4):
        super().__init__()
        self.stopped = Event()
        self.sniff_iface = interface
        self.sniff_filter = filter
        self.sniff_thread = None
        self.queue = Queue(MonitoringModule.QUEUE_SIZE)

        self.mode = mode
        if mode == MonitoringModule.MODE_IPV4:
            self.ip_layer = IP
        else:
            self.ip_layer = IPv6
        self.iface_ip = self.iface_ip(interface, mode)

    @staticmethod
    def execution_time() -> int:
        return round(time.time() - MonitoringModule.START_TIME)

    @staticmethod
    def iface_ip(iface: str, mode=MODE_IPV4) -> str:
        cmd = 'ip addr show '+iface
        split = mode + ' '
        return os.popen(cmd).read().split(split)[1].split("/")[0]
    
    def start_sniffing(self):
        self.sniff_thread = SniffThread.instance(iface=self.sniff_iface, filter='')
        self.sniff_thread.start_sniffing(self.queue, self.stopped)

    def stop_execution(self):
        self.stopped.set()

    def classify_packet(self, packet: Packet, port_map: dict, iface_ip: str) -> (str, str):
        traffic_type = None
        port = None

        if self.ip_layer in packet:
            if iface_ip in packet[self.ip_layer].src:
                traffic_type = MonitoringModule.TRAFFIC_OUTBOUND
            else:
                traffic_type = MonitoringModule.TRAFFIC_INBOUND
        if TCP in packet:
            #packet port is the client dport or the server sport
            if packet.sport in port_map:
                port = packet.sport
            else:
                port = packet.dport

        return port, traffic_type


class DictTools:
    @staticmethod
    def add_multiple_key_single_value(keys: list=[], value=None, dictionary: dict={}):
        for key in keys:
            dictionary[key] = value

    @staticmethod
    def invert(dictionary: dict) -> dict:
        new_dict = {}
        for key in dictionary:
            for value in dictionary[key]:
                new_dict[value] = key
        return new_dict
