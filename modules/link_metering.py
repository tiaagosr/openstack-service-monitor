from scapy.all import IP, Packet, sniff, TCP
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
        print(self.metering_result)
        return self.metering_result

    def is_ephemeral_port(self, port):
        if port != 35357 and 32768 <= port <= 60999:
            return True
        return False

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

    def _db_init_persistance(self, cursor):
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, type VARCHAR(5), interface VARCHAR(40), m_etc INTEGER, m_nova INTEGER, m_keystone INTEGER, m_glance INTEGER, m_cinder INTEGER, m_swift INTEGER, m_ceph INTEGER, etc_ports TEXT, ignored_count INTEGER, time DATE)''')

    def init_persistance(self):
        self.db.create_conn()
        self.db.wrap_access(self._db_init_persistance)

    def _db_persist_result(self, cursor, result):
        exec_time = self.execution_time()
        for traffic_type in result:
            cursor.execute('''INSERT INTO link_usage (interface, type, time, ignored_count, m_cinder, m_etc, m_glance, m_keystone, m_nova, m_swift, m_ceph, etc_ports) 
                VALUES ("{iface}", "{type}", time({time}, 'unixepoch'), "{ignored_count}", "{cinder}", "{etc}", "{glance}", "{keystone}", "{nova}", "{swift}", "{ceph}", "{etc_ports}")'''
                .format(iface=self.sniff_iface, type=traffic_type, time=exec_time, ignored_count=str(self.ignored_count), **result[traffic_type]))

    def persist_metering_result(self, result: dict = {}):
        for traffic_type in result:
            current_result = result[traffic_type]
            if 'etc_ports' in current_result:
                top_ports = [(a, int(x)) for a, x in current_result['etc_ports'].items()]
                sorted_top_ports = sorted(top_ports, key=lambda x: x[1], reverse=True)[:10]
                current_result['etc_ports'] = json.dumps(sorted_top_ports)
                print(current_result['etc_ports'])
        self.db.wrap_access(self._db_persist_result, result)

    def _db_print_results(self, cursor):
        result = cursor.execute("SELECT * FROM link_usage ORDER BY time DESC LIMIT 1")
        print(result.fetchone())

    def print_results(self):
        self.db.wrap_access(self._db_print_results)
