from peewee import *
from playhouse.sqlite_ext import JSONField
from scapy.layers.l2 import Ether
from scapy_http.http import *
from modules.api_mapper import get_action
from modules.definitions import MonitoringModule, DictTools, MonitoringSession
import dpkt
import math
import datetime


def difference_secs(a, b):
    if a is None or b is None:
        return 0
    return int(math.floor((b - a).total_seconds()))

# BPF Filter for the sniffing socket. It listens for tcp packets in which dport contains values from ApiLogging.MAP.values()
DEFAULT_API_BPF = [
    [0x28, 0, 0, 0x0000000c],
    [0x15, 0, 5, 0x000086dd],
    [0x30, 0, 0, 0x00000014],
    [0x15, 6, 0, 0x00000006],
    [0x15, 0, 32, 0x0000002c],
    [0x30, 0, 0, 0x00000036],
    [0x15, 3, 30, 0x00000006],
    [0x15, 0, 29, 0x00000800],
    [0x30, 0, 0, 0x00000017],
    [0x15, 0, 27, 0x00000006],
    [0x28, 0, 0, 0xfffff004],
    [0x15, 25, 0, 0x00000004],
    [0x28, 0, 0, 0x0000000c],
    [0x15, 0, 6, 0x000086dd],
    [0x30, 0, 0, 0x00000014],
    [0x15, 2, 0, 0x00000084],
    [0x15, 1, 0, 0x00000006],
    [0x15, 0, 19, 0x00000011],
    [0x28, 0, 0, 0x00000038],
    [0x15, 16, 10, 0x00001f90],
    [0x15, 0, 16, 0x00000800],
    [0x30, 0, 0, 0x00000017],
    [0x15, 2, 0, 0x00000084],
    [0x15, 1, 0, 0x00000006],
    [0x15, 0, 12, 0x00000011],
    [0x28, 0, 0, 0x00000014],
    [0x45, 10, 0, 0x00001fff],
    [0xb1, 0, 0, 0x0000000e],
    [0x48, 0, 0, 0x00000010],
    [0x15, 6, 0, 0x00001f90],
    [0x15, 5, 0, 0x000025e0],
    [0x15, 4, 0, 0x00001388],
    [0x15, 3, 0, 0x00002246],
    [0x15, 2, 0, 0x00002248],
    [0x15, 1, 0, 0x0000244c],
    [0x15, 0, 1, 0x00008a1d],
    [0x6, 0, 0, 0x00040000],
    [0x6, 0, 0, 0x00000000],
]


class ApiLogging(MonitoringModule):
    MAP = {
        'nova': {8774},
        'keystone': {5000, 35357},
        'swift': {8080},
        #'glance': {9292},
        'cinder': {8776},
        'neutron': {9696},
        #'ceph': {6789},
    }

    REQUEST_MAP = {

    }

    def __init__(self, bpf=DEFAULT_API_BPF, pcap: str=None, **kwargs):
        self.port_mapping = DictTools.invert(ApiLogging.MAP)
        super().__init__(**kwargs)
        self.services = list(ApiLogging.MAP.keys())
        self._bind_ports_http()
        # self.create_filter_string(list(self.port_mapping.keys()))
        self.init_db(self.db_path)
        self.pcap = pcap

    @staticmethod
    def create_filter_string(ports):
        sniff_filter = 'tcp and inbound and ('
        for i, p in enumerate(ports):
            if i > 0:
                sniff_filter += ' or'
            sniff_filter += ' dst port ' + str(p)
        sniff_filter += ')'
        print(sniff_filter)
        return sniff_filter

    @staticmethod
    def init_db(path):
        ApiLogging.DATABASE.init(path)
        ApiLogging.DATABASE.connect()
        ApiLogging.DATABASE.create_tables([ApiData])

    def _bind_ports_http(self):
        for port in self.port_mapping:
            bind_layers(TCP, HTTP, sport=port)
            bind_layers(TCP, HTTP, dport=port)

    def measure_packet(self, packet_bytes, time):
        packet = Ether(packet_bytes)
        if not packet.haslayer(HTTP):
            return
        port = self.classify_packet(packet, self.port_mapping)
        if port is None:
            return

        new_entry = ApiData(services=self.services, service_port_map=self.port_mapping, time=time, session=self.session)
        new_entry.set_service(port)
        new_entry.set_action(packet)
        new_entry.set_method(packet)
        new_entry.save()

    def run(self):
        max_time, min_time = None, None
        for ts, _ in dpkt.pcap.Reader(open(self.pcap, 'rb')):
            current_time = datetime.datetime.utcfromtimestamp(ts)
            if max_time is None or current_time > max_time:
                max_time = current_time
            if min_time is None or current_time < min_time:
                min_time = current_time

        for ts, packet in dpkt.pcap.Reader(open(self.pcap, 'rb')):
            current_time = datetime.datetime.utcfromtimestamp(ts)
            self.measure_packet(packet, difference_secs(min_time, current_time))
        print("API Logging finished!")

    def start_monitoring(self):
        print("Logging API Access")
        self.start_sniffing()
        self.start()


class ApiData(Model):
    session = ForeignKeyField(MonitoringSession, backref='api_log')
    time = TimeField(formats='%H:%M:%S')
    content = JSONField(default={})
    action = CharField()
    service = CharField()
    method = CharField()

    class Meta:
        database = ApiLogging.DATABASE

    def __init__(self, services=None, service_port_map=DictTools.invert(ApiLogging.MAP), **kwargs):
        super(ApiData, self).__init__(**kwargs)
        self.map = service_port_map
        self.services = services

    def set_service(self, port):
        self.service = self.get_mapping(port)
        return self

    def set_method(self, packet):
        self.method = packet.Method
        return self

    def get_mapping(self, port):
        if port in self.map:
            return self.map[port]
        return 'etc'

    def set_action(self, packet):
        self.action = get_action(self.service, packet)

    def content(self):
        attrs = {'type': self.type, 'time': self.time, 'content': self.content, 'service': self.service}
        return attrs

    def __str__(self):
        return str(self.content())

    def save(self, force_insert=False, only=None):
        super(ApiData, self).save(force_insert, only)