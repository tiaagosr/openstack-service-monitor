from threading import Thread, Event, Lock
from scapy.all import IP, Packet, sniff, TCP
from queue import Queue
from database import DBSession
from modules.definitions import MonitoringModule, DictTools
import json

# Inbound and Outbound: self.metering_result
class LinkMetering(MonitoringModule):
    MAP = {
        'nova': set([5900, 6080, 6081, 6082, 8773, 8774, 8775] + list(range(5900, 5999))),
        'keystone': set([5000, 35357]),
        'swift': set([873, 6000, 6001, 6002, 8080]),
        'glance': set([9191, 9292]),
        'cinder': set([3260, 8776]),
        'neutron': set([9696]),
        'ceilometer': set([8777]),
        'ceph': set([6800, 7300])
    }

    DEFAULT_INTERVAL = 10

    def __init__(self, db_path, iface='wlp2s0', sniff_filter='tcp', interval=DEFAULT_INTERVAL, mode=MonitoringModule.MODE_IPV4):
        super().__init__(iface, sniff_filter, mode)
        self.aux_thread_interval = interval
        self.port_mapping = DictTools.invert(LinkMetering.MAP)
        self.services = LinkMetering.MAP.keys()
        self.buffer_params = {'iface': self.sniff_iface, 'services': self.services, 'interval': self.aux_thread_interval, 'service_port_map': self.port_mapping}
        tmp_buffer = self._setup_buffer()
        self.buffer = {MonitoringModule.TRAFFIC_INBOUND: tmp_buffer[0], MonitoringModule.TRAFFIC_OUTBOUND: tmp_buffer[1]}
        self.persistance_thread = None
        self.db_path = db_path
        self.db_lock = Lock()

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

    def _setup_buffer(self):
        inbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_INBOUND, **self.buffer_params)
        outbound_buffer = MeteringData(type=MonitoringModule.TRAFFIC_OUTBOUND, **self.buffer_params)
        return inbound_buffer, outbound_buffer

    def calculate_usage(self):
        while not self.stopped.is_set():
            if not self.queue.empty():
                with self.db_lock:
                    if len(self.buffer) == 0:
                        tmp_buffer = self._setup_buffer()
                        self.buffer[MonitoringModule.TRAFFIC_INBOUND] = tmp_buffer[0]
                        self.buffer[MonitoringModule.TRAFFIC_OUTBOUND] = tmp_buffer[1]
                    packet = self.queue.get()
                    self.measure_packet(packet)

    def run(self):
        self.init_persistance()
        self.calculate_usage()

    def init_persistance(self):
        self.persistance_thread = LinkMeteringPersistence(self.buffer, self.db_lock, self.aux_thread_interval, list(self.services), self.db_path)
        self.persistance_thread.start()

    def start_monitoring(self):
        print("Metering link usage, interval: " + str(self.aux_thread_interval)+"\niface ip: "+self.iface_ip)
        self.start_sniffing()
        self.start()


class MeteringData:
    def __init__(self, iface='', type=MonitoringModule.TRAFFIC_OUTBOUND, services=LinkMetering.MAP.keys(), service_port_map=DictTools.invert(LinkMetering.MAP), interval=LinkMetering.DEFAULT_INTERVAL):
        self.iface = iface
        self.type = type
        self.map = service_port_map
        self.interval = interval
        self.time = None
        self.ignored_count = 0
        self.services = self.init_services(services)
        self.port_buffer = {}
        self.etc_port_buffer = {}
        self.etc_ports = []

    def __getitem__(self, item):
        if item == 'etc':
            return self.services['etc']
        if not isinstance(item, int):
            raise TypeError('Metering port must be int or str("etc")')
        return self.port_buffer.get(item, 0)

    def __setitem__(self, key, value):
        if key == 'etc':
            self.services['etc'] = value
        if not isinstance(key, int):
            raise TypeError('Metering port must be int or str("etc")')
        self.port_buffer[key] = value

    def init_services(self, service_list):
        services = {x: 0 for x in service_list}
        services['etc'] = 0
        return services

    def calculate_metering(self):
        for port in self.port_buffer:
            usage = round(self[port] / self.interval)
            service = self.classify_port(port)
            self.port_calculation(port, service, usage)
        self._sort_etc_ports()

    def port_calculation(self, port, service, usage):
        # uncategorized port
        if service == 'etc' and not self._is_ephemeral(port):
            self.etc_port_buffer[port] = usage
        self.services[service] += usage

    def classify_port(self, port):
        if port in self.map:
            return self.map[port]
        return 'etc'

    def _is_ephemeral(self, port):
        return port != 35357 and 32768 <= port <= 60999

    def _sort_etc_ports(self, max_position=10):
        top_ports = [{'port': a, 'value': int(x)} for a, x in self.etc_port_buffer.items()]
        self.etc_ports = sorted(top_ports, key=lambda x: x['value'], reverse=True)[:max_position]

    def content(self):
        attrs = {'iface': self.iface, 'type': self.type, 'time': self.time, 'ignored_count': self.ignored_count, 'etc_ports': json.dumps(self.etc_ports)}
        return {**attrs, **self.services}

    def __str__(self):
        return self.content()


class LinkMeteringPersistence(Thread):
    def __init__(self, buffer, lock, interval, services=['etc'], dbpath=':memory:'):
        super().__init__()
        self.db = DBSession(dbpath)
        self.services = services
        self.persist_query = ''
        self.stopped = Event()
        self.buffer = buffer
        self.lock = lock
        self.interval = interval

    def _generate_metering_query(self, fields: list, traffic_type=None) -> str:
        query = 'SELECT '
        first = True
        # Generate query based on service list
        for f in fields:
            if first:
                first = False
                query += f
            else:
                query += ', '+f
        query += ' FROM link_usage'
        if traffic_type is not None:
            query += ' where type="{type}"'.format(type=traffic_type)
        query += ' ORDER BY id'
        return query

    def service_data(self, traffic_type=None):
        self.db.wrap_access(self._service_data, traffic_type)

    def _service_data(self, cursor, traffic_type=None):
        fields = ['time']
        for service in self.services:
            fields.append('m_'+service)
        query = self._generate_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def etc_port_data(self, traffic_type=None):
        self.db.wrap_access(self._etc_port_data, traffic_type)

    def _etc_port_data(self, cursor, traffic_type):
        fields = ['m_etc', 'etc_ports', 'time', 'type']
        query = self._generate_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def persist_result(self, result: MeteringData):
        self.db.wrap_access(self._persist_result, result)

    def _persist_result(self, cursor, result: MeteringData):
        query = str(self.persist_query).format(**result.content())
        cursor.execute(query)

    def stop_execution(self):
        self.stopped.set()

    def _generate_table(self, cursor):
        query = 'CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, type VARCHAR(5), interface VARCHAR(40), etc_ports TEXT, ignored_count INTEGER, time DATE, m_etc INTEGER'
        # Generate query based on service list
        for service in self.services:
            query += ', m_'+service+' INTEGER'
        query += ')'
        cursor.execute(query)

    def _generate_persist_query(self):
        query = 'INSERT INTO link_usage ('
        fields = 'interface, type, time, ignored_count, etc_ports, m_etc'
        values = '''"{iface}", "{type}", time({time}, "unixepoch"), "{ignored_count}", '{etc_ports}', "{etc}"'''
        for service in self.services:
            fields += ', m_'+service
            values += ', "{'+service+'}"'
        query += fields+') VALUES ('+values+')'
        return query

    def init_persistance(self):
        self.db.create_conn()
        self.db.wrap_access(self._generate_table)
        self.persist_query = self._generate_persist_query()

    def run(self):
        self.init_persistance()
        while not self.stopped.wait(self.interval):
            time = MonitoringModule.execution_time()
            with self.lock:
                for item in self.buffer:
                    self.buffer[item].time = time
                    self.buffer[item].calculate_metering()
                    self.persist_result(self.buffer[item])
                self.buffer.clear()
