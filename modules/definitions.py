from threading import Thread, Event
from scapy.all import sniff, Packet, TCP, IP, IPv6
from queue import Queue
import os
import time


class SniffThread(Thread):
    def __init__(self, shared_queue: Queue, filter='', iface=''):
        super().__init__()
        self.queue = shared_queue
        self.stopped = Event()
        self.filter = filter
        self.iface = iface

    def run(self):
        while not self.stopped.is_set() and not self.queue.full():
            data = sniff(iface=self.iface, filter=self.filter, count=1)
            [self.queue.put(item) for item in data]

    def stop_execution(self):
        self.stopped.set()


class MonitoringModule(Thread):
    MODE_IPV4 = 0
    MODE_IPV6 = 1
    TRAFFIC_OUTBOUND = 'out'
    TRAFFIC_INBOUND = 'in'
    QUEUE_SIZE = 1000
    START_TIME = time.time()

    def __init__(self, iface='lo', filter='tcp', mode=MODE_IPV4):
        super().__init__()
        self.stopped = Event()
        self.sniff_iface = iface
        self.sniff_filter = filter
        self.sniff_thread = None
        self.queue = Queue(MonitoringModule.QUEUE_SIZE)

        self.mode = mode
        if mode == MonitoringModule.MODE_IPV4:
            self.ip_layer = IP
        else:
            self.ip_layer = IPv6
        self.iface_ip = self.iface_ip(iface, mode)

    @staticmethod
    def execution_time() -> int:
        return round(time.time() - MonitoringModule.START_TIME)

    def iface_ip(self, iface: str, mode=MODE_IPV4) -> str:
        cmd = 'ip addr show '+iface
        if mode == MonitoringModule.MODE_IPV6:
            split = "inet6 "
        else:
            split = "inet "
        return os.popen(cmd).read().split(split)[1].split("/")[0]
    
    def start_sniffing(self):
        self.sniff_thread = SniffThread(self.queue, iface=self.sniff_iface, filter=self.sniff_filter)
        self.sniff_thread.start()

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
