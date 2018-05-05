from threading import Thread
from modules.pcap import PcapWriter
from peewee import *
from playhouse.sqlite_ext import JSONField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from modules.definitions import MonitoringModule, DictTools, MonitoringSession
import json


class LinkMetering(MonitoringModule):
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

    DEFAULT_INTERVAL = 1

    DEFAULT_BUFFER_SIZE = 2**30  # 1024MB

    def __init__(self, interval: int=DEFAULT_INTERVAL, pcap: str=None, **kwargs):
        super().__init__(**kwargs)
        self.aux_thread_interval = interval
        self.sniffer.sniffer.set_buffer_size(LinkMetering.DEFAULT_BUFFER_SIZE)
        self.port_mapping = DictTools.invert(LinkMetering.MAP)
        self.services = LinkMetering.MAP.keys()
        self.buffer_params = {'interface': self.sniff_iface, 'services': self.services, 'interval': self.aux_thread_interval, 'service_port_map': self.port_mapping, 'session': self.session}
        self.buffer = None
        self.reset_buffer()
        self.init_db(self.db_path)
        self.persistence = LinkMeteringPersistence()
        self.pcap = pcap

    @staticmethod
    def init_db(path):
        LinkMetering.DATABASE.init(path)
        LinkMetering.DATABASE.connect()
        LinkMetering.DATABASE.create_tables([MeteringData])

    def measure_packet(self, traffic_type, packet_bytes):
        packet = Ether(packet_bytes)
        traffic_type = self.packet_type(traffic_type)

        port = self.classify_packet(packet, self.port_mapping)

        buffer = self.buffer[traffic_type]

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
        elif traffic_type is not None:
            buffer['etc'] += plen

    def reset_buffer(self):
        inbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_INBOUND, **self.buffer_params)
        outbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_OUTBOUND, **self.buffer_params)
        self.buffer = {MonitoringModule.TRAFFIC_INBOUND: inbound_buffer,
                       MonitoringModule.TRAFFIC_OUTBOUND: outbound_buffer}
        return self.buffer

    def run(self):
        self.persistence.timed_storage(self.buffer, self.aux_thread_interval, self.stopped, self.reset_buffer)
        pcap = None
        if self.pcap is not None:
            pcap = PcapWriter(self.pcap)
        while True:
            try:
                traffic_type, packet = self.conn.recv()
            except EOFError:
                break
            # Producer finished sniffing
            if packet is None:
                break
            # Write to pcap file if provided path
            if pcap is not None:
                pcap.write(packet)
            self.measure_packet(traffic_type, packet)
        self.module_cleanup(pcap)
        print("Link Metering: Execution finished!")

    def start_monitoring(self):
        print("Link Metering: Execution Started, interval: " + str(self.aux_thread_interval)+"\niface ip: "+self.iface_ip)
        self.start_sniffing()
        self.start()

    def module_cleanup(self, pcap):
        self.cleanup()
        if pcap is not None:
            pcap.flush()
            pcap.close()


class MeteringData(Model):
    type = CharField()
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

    def __init__(self, services=None, service_port_map=DictTools.invert(LinkMetering.MAP),
                 interval=LinkMetering.DEFAULT_INTERVAL, **kwargs):
        super(MeteringData, self).__init__(**kwargs)
        self.map = service_port_map
        self.interval = interval
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
            usage = round(self[port] / self.interval)
            service = self.classify_port(port)
            self.port_calculation(port, service, usage)
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
        attrs = {'interface': self.interface, 'type': self.type, 'time': self.time, 'ignored_count': self.ignored_count, 'etc_ports': json.dumps(self.etc_ports), 'etc': self.etc}
        return {**attrs, **services}

    def __str__(self):
        return str(self.content())

    def save(self, force_insert=False, only=None):
        self.calculate_metering()
        self.calculate_total()
        self._sort_etc_ports()
        super(MeteringData, self).save(force_insert, only)


class LinkMeteringPersistence(Thread):
    def __init__(self):
        super().__init__()
        self.stopped = None
        self.buffer = None
        self.interval = None
        self.buffer_reset = None

    def timed_storage(self, buffer, interval, stop_event, buffer_reset):
        self.buffer = buffer
        self.buffer_reset = buffer_reset
        self.interval = interval
        self.stopped = stop_event
        self.start()

    def run(self):
        while not self.stopped.wait(self.interval):
            exec_time = MonitoringModule.execution_time()

            buffer = self.buffer
            self.buffer = self.buffer_reset()

            for item in buffer:
                buffer[item].time = exec_time
                buffer[item].save()
            buffer.clear()
