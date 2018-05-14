from peewee import *
from playhouse.sqlite_ext import JSONField
from scapy.layers.l2 import Ether
from scapy_http.http import *
from modules.api_mapper import get_action
from modules.definitions import PcapAnalysisModule, DictTools, MonitoringSession
import dpkt
import datetime


class ApiLogging(PcapAnalysisModule):
    MAP = {
        'nova': {8774},
        'keystone': {5000, 35357},
        'swift': {8080},
        'glance': {9292},
        'cinder': {8776},
        'neutron': {9696},
        #'ceph': {6789},
    }

    def __init__(self, **kwargs):
        self.port_mapping = DictTools.invert(self.MAP)
        super().__init__(**kwargs)
        self.services = list(self.MAP.keys())
        self._bind_ports_http()
        self.init_db(self.db_path)

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
        if not packet.haslayer(HTTPRequest):
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
            self.measure_packet(packet, self.difference_in_secs(min_time, current_time))
        print("API analysis finished!")


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
