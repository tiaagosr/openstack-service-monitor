from peewee import *
from playhouse.sqlite_ext import JSONField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from modules.definitions import PcapAnalysisModule, DictTools, MonitoringSession
import json
import dpkt
import datetime


class LinkMetering(PcapAnalysisModule):
    MAP = {
        'nova': set([5900, 6080, 6081, 6082, 8773, 8774, 8775] + list(range(5900, 5999))),
        'keystone': {5000, 35357},
        'swift': {873, 6000, 6001, 6002, 8080},
        'glance': {9191, 9292},
        'cinder': {3260, 8776},
        'neutron': {9696},
        'ceilometer': {8777},
        'ceph': {6800, 7300}
    }

    SERVICES = MAP.keys()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.port_mapping = DictTools.invert(self.MAP)
        self.services = self.MAP.keys()
        self.buffer_params = {'services': self.services, 'service_port_map': self.port_mapping, 'session': self.session}
        self.buffer = {}
        self.init_db(self.db_path)

    @staticmethod
    def init_db(path):
        LinkMetering.DATABASE.init(path)
        LinkMetering.DATABASE.connect()
        LinkMetering.DATABASE.create_tables([MeteringData])

    def measure_packet(self, packet_bytes, buffer):
        packet = Ether(packet_bytes)

        port = self.classify_packet(packet, self.port_mapping)

        if IPv6 in packet:
            plen = packet.plen
        elif IP in packet:
            plen = packet.len
        else:
            buffer.ignored_count += 1
            return

        if port is not None:
            buffer[port] += plen
        # Packet without TCP Layer (subsequently, without destination port)
        elif packet.haslayer(TCP):
            buffer['etc'] += plen

    def get_buffer(self, time):
        if time not in self.buffer:
            self.buffer[time] = MeteringData(**self.buffer_params, time=time)
        return self.buffer[time]

    def run(self):
        print("Starting dump analysis at "+self.pcap+"!")

        # Loopback traffic
        if self.pcap_lo is not None:
            max_time, min_time = None, None
            for ts, _ in dpkt.pcap.Reader(open(self.pcap_lo, 'rb')):
                current_time = datetime.datetime.utcfromtimestamp(ts)
                if max_time is None or current_time > max_time:
                    max_time = current_time
                if min_time is None or current_time < min_time:
                    min_time = current_time

            for time in range(0, self.difference_in_secs(max_time, min_time)):
                self.get_buffer(time)

            for ts, pkt in dpkt.pcap.Reader(open(self.pcap_lo, 'rb')):
                current_time = self.difference_in_secs(datetime.datetime.utcfromtimestamp(ts), min_time)
                buffer = self.get_buffer(current_time)
                self.measure_packet(pkt, buffer)

        max_time, min_time = None, None
        for ts, _ in dpkt.pcap.Reader(open(self.pcap, 'rb')):
            current_time = datetime.datetime.utcfromtimestamp(ts)
            if max_time is None or current_time > max_time:
                max_time = current_time
            if min_time is None or current_time < min_time:
                min_time = current_time

        for time in range(0, self.difference_in_secs(max_time, min_time)):
            self.get_buffer(time)

        for ts, pkt in dpkt.pcap.Reader(open(self.pcap, 'rb')):
            current_time = self.difference_in_secs(datetime.datetime.utcfromtimestamp(ts), min_time)
            buffer = self.get_buffer(current_time)
            self.measure_packet(pkt, buffer)

        for k, v in sorted(self.buffer.items()):
            v.save()
        print("Link Metering: Execution finished!")

    def start_analysis(self):
        self.start()


class MeteringData(Model):
    session = ForeignKeyField(MonitoringSession, backref='link_data')
    time = TimeField(formats='%H:%M:%S')
    ignored_count = IntegerField(default=0)
    etc_ports = JSONField(default={})
    etc = IntegerField(default=0, column_name='m_etc')
    nova = IntegerField(default=0, column_name='m_nova')
    keystone = IntegerField(default=0, column_name='m_keystone')
    swift = IntegerField(default=0, column_name='m_swift')
    glance = IntegerField(default=0, column_name='m_glance')
    cinder = IntegerField(default=0, column_name='m_cinder')
    neutron = IntegerField(default=0, column_name='m_neutron')
    ceilometer = IntegerField(default=0, column_name='m_ceilometer')
    ceph = IntegerField(default=0, column_name='m_ceph')
    total = IntegerField(default=0, column_name='m_total')

    class Meta:
        database = LinkMetering.DATABASE

    def __init__(self, services=None, service_port_map=DictTools.invert(LinkMetering.MAP), **kwargs):
        super(MeteringData, self).__init__(**kwargs)
        self.map = service_port_map
        self.services = services
        if services is not None:
            self.init_services(services)
        self.port_buffer = {}
        self.etc_port_buffer = {}

    def __getitem__(self, item):
        if item in self.services or item == 'etc':
            return getattr(self, item, 0)
        if not isinstance(item, int):
            raise TypeError('Metering index must be int (Port) or str (Service)')
        return self.port_buffer.get(item, 0)

    def __setitem__(self, key, value):
        if key in self.services or key == 'etc':
            return setattr(self, key, value)
        if not isinstance(key, int):
            raise TypeError('Metering index must be int (Port) or str (Service)')
        self.port_buffer[key] = value

    def init_services(self, service_list):
        map(lambda x: setattr(self, x, 0), service_list)
        self.etc = 0

    def calculate_metering(self):
        for port in self.port_buffer:
            service = self.classify_port(port)
            self.port_calculation(port, service, self[port])
        self._sort_etc_ports()

    def calculate_total(self):
        self.total = self['etc']
        for service in self.services:
            self.total += self[service]

    def port_calculation(self, port, service, usage):
        # uncategorized port
        if service == 'etc' and not self.is_ephemeral(port):
            self.etc_port_buffer[port] = usage
        self[service] += usage

    def classify_port(self, port):
        if port in self.map:
            return self.map[port]
        return 'etc'

    @staticmethod
    def is_ephemeral(port):
        return port != 35357 and 32768 <= port <= 60999

    def _sort_etc_ports(self, max_position=10):
        top_ports = [{'port': a, 'value': int(x)} for a, x in self.etc_port_buffer.items()]
        self.etc_ports = sorted(top_ports, key=lambda x: x['value'], reverse=True)[:max_position]

    def content(self):
        services = {x: getattr(self, x, 0) for x in self.services}
        attrs = {'time': self.time, 'ignored_count': self.ignored_count, 'etc_ports': json.dumps(self.etc_ports), 'etc': self.etc}
        return {**attrs, **services}

    def __str__(self):
        return str(self.content())

    def save(self, force_insert=False, only=None):
        self.calculate_metering()
        self.calculate_total()
        self._sort_etc_ports()
        super(MeteringData, self).save(force_insert, only)