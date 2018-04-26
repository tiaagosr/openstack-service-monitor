import socket
from threading import Thread, Event
import multiprocessing as mp
from peewee import SqliteDatabase
from modules.sniffer import IPSniff
from scapy.layers.inet import IP, TCP, Packet
from scapy.layers.inet6 import IPv6
from scapy.all import sniff
import os
import time


class PacketSniffer(mp.Process):

    def __init__(self, iface, data_pipe):
        super().__init__()
        self.pipe = data_pipe
        self.stopped = Event()
        self.iface = iface
        self.sniffer = None

    def start_sniffing(self):
        self.start()

    def store_packet(self, direction, packet):
        self.pipe.send((direction, packet))

    def run(self):
        self.sniffer = IPSniff(self.iface, callback=self.store_packet)
        self.sniffer.recv()
        print("Sniffer thread Stopped!")


class PortSniffer(mp.Process):

    def __init__(self, iface, sniff_filter, data_pipe):
        super().__init__()
        self.pipe = data_pipe
        self.stopped = Event()
        self.iface = iface
        self.sniff_filter = sniff_filter
        self.sniffer = None

    def start_sniffing(self):
        self.start()

    def store_packet(self, packet):
        self.pipe.send(packet)

    def run(self):
        self.sniffer = sniff(store=0, filter=self.sniff_filter, iface=self.iface, prn=self.store_packet)
        print("Sniffer thread Stopped!")


class MonitoringModule(Thread):
    MODE_IPV4 = 'inet'
    MODE_IPV6 = 'inet6'
    TRAFFIC_OUTBOUND = 'out'
    TRAFFIC_INBOUND = 'in'
    START_TIME = time.time()
    DATABASE = SqliteDatabase(None)

    @staticmethod
    def packet_type(traffic_type):
        if traffic_type == socket.PACKET_OUTGOING:
            return MonitoringModule.TRAFFIC_OUTBOUND
        return MonitoringModule.TRAFFIC_INBOUND

    def __init__(self, interface='lo', mode=MODE_IPV4, sniff_filter=None):
        super().__init__()
        self.stopped = Event()
        self.sniff_iface = interface
        recv_pipe, send_pipe = mp.Pipe(duplex=False)
        self.pipe = recv_pipe
        if sniff_filter is not None:
            self.sniffer = PortSniffer(interface, sniff_filter, send_pipe)
        else:
            self.sniffer = PacketSniffer(self.sniff_iface, send_pipe)

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
        self.sniffer.start_sniffing()

    def stop_sniffing(self):
        self.sniffer.terminate()
        self.pipe.close()
        self.sniffer.join()

    def stop(self):
        self.stop_sniffing()
        self.stop_execution()

    def stop_execution(self):
        self.stopped.set()

    @staticmethod
    def classify_packet(packet: Packet, port_map: dict) -> str:
        port = None

        if TCP in packet:
            #packet port is the client dport or the server sport
            if packet.sport in port_map:
                port = packet.sport
            else:
                port = packet.dport

        return port


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
