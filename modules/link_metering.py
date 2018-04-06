from scapy.all import IP, Packet, sniff, TCP

from database import DBSession
from modules.definitions import MonitoringModule, DictionaryInit
import json

# Inbound and Outbound: self.metering_result
class LinkMetering(MonitoringModule):
    def __init__(self, dbpath, iface='wlp2s0', sniff_filter='tcp', interval=10, mode=MonitoringModule.MODE_IPV4):
        super().__init__(iface, sniff_filter, self.measure_packet, dbpath, mode)
        self.aux_thread_interval = interval
        self.ignored_count = 0
        self.dict = DictionaryInit()
        self.metering_buffer = self.dict.metering_buffer()
        self.metering_result = self.dict.metering_dictionary()
        self.port_mapping = self.dict.metering_ports()

    def measure_packet(self, packet):
        port, traffic_type = self.classify_packet(packet, self.port_mapping, self.iface_ip)
        if port is not None:
            port_sum = self.metering_buffer.get(port, 0)
            self.metering_buffer[traffic_type][port] = packet.len + port_sum
        # Packet without TCP Layer (subsequently, without destination port)
        elif traffic_type is not None:
            self.metering_result[traffic_type]['etc'] += packet.len
        # Packet without IP layer
        else:
            self.ignored_count += 1

    def calculate_and_persist(self):
        # Shallow copy dict shared by threads
        metering_result_copy = dict(self.calculate_usage())
        self.persist_metering_result(metering_result_copy)
        del metering_result_copy
        # reset values
        self.metering_result = self.dict.metering_dictionary()
        self.ignored_count = 0

    def calculate_usage(self):
        # Shallow copy dict shared by threads
        buffer_copy = dict(self.metering_buffer)
        self.metering_buffer = self.dict.metering_buffer()
        for traffic_type in buffer_copy:
            for port in buffer_copy[traffic_type]:
                port_usage = round(buffer_copy[traffic_type][port] / self.aux_thread_interval)
                service = self.classify_port(port)
                # uncategorized port
                if service == 'etc' and not self.is_ephemeral_port(port):
                    self.metering_result[traffic_type]['etc_ports'][port] = port_usage
                self.metering_result[traffic_type][service] += port_usage
        del buffer_copy
        return self.metering_result

    def is_ephemeral_port(self, port):
        return port != 35357 and 32768 <= port <= 60999

    def run(self):
        self.init_persistance()
        while not self.stopped.wait(self.aux_thread_interval):
            self.calculate_and_persist()

    def classify_port(self, port):
        if port in self.port_mapping:
            return self.port_mapping[port]
        return 'etc'

    def start_monitoring(self):
        print("Metering link usage, interval: " + str(self.aux_thread_interval)+"\niface ip: "+self.iface_ip)
        self.start_sniffing()
        self.start()

    def persist_metering_result(self, result: dict = {}):
        for traffic_type in result:
            current_result = result[traffic_type]
        self.db.wrap_access(self._db_persist_result, result)


class MeteringData:
    def __init__(self, iface = '', type = '', time = None, ignore_count = 0, etc_ports = [], services = {'etc': 0}):
        self.iface = iface
        self.type = type
        self.time = time
        self.ignored_count = ignore_count
        self.etc_ports = etc_ports
        self.services = services

    def add_etc_ports(self, ports):
        top_ports = [{'port': a, 'value': int(x)} for a, x in ports.items()]
        self.etc_ports = sorted(top_ports, key=lambda x: x['value'], reverse=True)[:10]

    def content(self):
        attrs = {'iface': self.iface, 'type': self.type, 'time': self.time, 'ignored_count': self.ignored_count, 'etc_ports': json.dumps(self.etc_ports)}
        return {**attrs, **self.services}

    def __str__(self):
        return self.content()


class LinkMeteringPersistence(DBSession):
    def __init__(self, services=['etc'], dbpath=':memory:'):
        super().__init__(dbpath)
        self.services = services
        self.persist_query = ''

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
        self.wrap_access(self._service_data, traffic_type)

    def _service_data(self, cursor, traffic_type=None):
        fields = ['time']
        for service in self.services:
            fields.append('m_'+service)
        query = self._generate_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def etc_port_data(self, traffic_type=None):
        self.wrap_access(self._etc_port_data, traffic_type)

    def _etc_port_data(self, cursor, traffic_type):
        fields = ['m_etc', 'etc_ports', 'time', 'type']
        query = self._generate_metering_query(fields, traffic_type)
        cursor.execute(query)
        return cursor.fetchall()

    def persist_result(self, result: MeteringData):
        self.wrap_access(self, result)

    def _persist_result(self, cursor, result: MeteringData):
        exec_time = self.execution_time()
        for traffic_type in result:
            str(self.persist_query).format(**result.content())

    def _generate_table(self, cursor):
        query = 'CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, type VARCHAR(5), interface VARCHAR(40), etc_ports TEXT, ignored_count INTEGER, time DATE, etc INTEGER'
        # Generate query based on service list
        for service in self.services:
            query += ', m_'+service+' INTEGER'
        cursor.execute(query)

    def _generate_persist_query(self):
        query = 'INSERT INTO link_usage ('
        fields = 'interface, type, time, ignored_count, etc_ports, m_etc'
        values = '"{iface}", "{type}", time({time}, "unixepoch"), "{ignored_count}", "{etc_ports}", "{m_etc}"'
        for service in self.services:
            fields += ', m_'+service
            values += ', "{'+service+'}"'
        query += fields+') VALUES ('+values+')'
        return query

    def init_persistance(self):
        self.create_conn()
        self.wrap_access(self._generate_table)
        self.persist_query = self._generate_persist_query()