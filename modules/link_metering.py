from threading import Thread, Lock
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from peewee import *
from playhouse.sqlite_ext import JSONField
from scapy.all import Packet
from modules.definitions import MonitoringModule, DictTools
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
        #'ceph': {6800, 7300}
    }

    SERVICES = MAP.keys()

    DEFAULT_INTERVAL = 10

    def __init__(self, db_path, iface='wlp2s0', sniff_filter='tcp', interval=DEFAULT_INTERVAL, mode=MonitoringModule.MODE_IPV4):
        super().__init__(iface, sniff_filter, mode)
        self.aux_thread_interval = interval
        self.port_mapping = DictTools.invert(LinkMetering.MAP)
        self.services = LinkMetering.MAP.keys()
        self.buffer_params = {'interface': self.sniff_iface, 'services': self.services, 'interval': self.aux_thread_interval, 'service_port_map': self.port_mapping}
        self.buffer = {}
        self.init_db(db_path)
        self.persistence = LinkMeteringPersistence()
        self.buffer_lock = Lock()

    @staticmethod
    def init_db(path, create_tables=True):
        LinkMetering.DATABASE.init(path)
        LinkMetering.DATABASE.connect()
        if create_tables:
            LinkMetering.DATABASE.create_tables([MeteringData])

    def measure_packet(self, packet):
        port, traffic_type = self.classify_packet(packet, self.port_mapping, self.iface_ip)
        if traffic_type is None:
            return

        buffer = self.buffer[traffic_type]

        if port is not None:
            buffer[port] += packet.len
        # Packet without TCP Layer (subsequently, without destination port)
        elif traffic_type is not None:
            buffer['etc'] += packet.len
        # Packet without IP layer
        else:
            buffer.ignored_count += 1

    def create_buffer(self):
        inbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_INBOUND, **self.buffer_params)
        outbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_OUTBOUND, **self.buffer_params)
        return (MonitoringModule.TRAFFIC_INBOUND, inbound_buffer), (MonitoringModule.TRAFFIC_OUTBOUND, outbound_buffer)

    def run(self):
        self.persistence.timed_storage(self.buffer, self.aux_thread_interval, self.buffer_lock, self.stopped)
        #Retain lock for the next 10000 items
        while not self.stopped.is_set():
            if not self.queue.empty():
                self.buffer_lock.acquire()
                packet = self.queue.get()
                if not self.buffer:
                    self.buffer.update(self.create_buffer())
                self.measure_packet(packet)
            elif self.buffer_lock.locked():
                self.buffer_lock.release()
        #Consumer Thread stopped > Stop persistence

    def start_monitoring(self):
        print("Metering link usage, interval: " + str(self.aux_thread_interval)+"\niface ip: "+self.iface_ip)
        self.start_sniffing()
        self.start()


class MeteringData(Model):
    interface = CharField()
    type = CharField()
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
    #ceph = IntegerField(default=0, column_name='m_ceph')

    class Meta:
        database = LinkMetering.DATABASE
        table_name = 'link_usage'

    def __init__(self, interface='', type=MonitoringModule.TRAFFIC_OUTBOUND, services=LinkMetering.MAP.keys(),
                 service_port_map=DictTools.invert(LinkMetering.MAP), interval=LinkMetering.DEFAULT_INTERVAL, **kwargs):
        super(MeteringData, self).__init__(interface=interface, type=type, **kwargs)
        self.map = service_port_map
        self.interval = interval
        self.services = services
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
        self._sort_etc_ports()
        super(MeteringData, self).save(force_insert, only)


class LinkMeteringPersistence(Thread):
    def __init__(self):
        super().__init__()
        self.stopped = None
        self.buffer = None
        self.lock = None
        self.interval = None

    def timed_storage(self, buffer, interval, lock, stop_event):
        self.buffer = buffer
        self.lock = lock
        self.interval = interval
        self.stopped = stop_event
        self.start()

    def run(self):
        while not self.stopped.wait(self.interval):
            time = MonitoringModule.execution_time()
            with self.lock:
                for item in self.buffer:
                    self.buffer[item].time = time
                    self.buffer[item].save()
                    print(self.buffer[item])
                self.buffer.clear()
