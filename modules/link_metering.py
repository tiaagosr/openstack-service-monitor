from scapy.all import IP, Packet, sniff, TCP
from threading import Thread, Timer, Event
from modules.definitions import MonitoringModule, DictionaryInit


class LinkMetering(MonitoringModule):
    def __init__(self, dbpath, iface='wlp2s0', filter='tcp', interval=10):
        super().__init__(iface, filter, self.measure_packet, dbpath)
        self.aux_thread_interval = interval
        self.ignored_count = 0
        self.metering_buffer = {}
        self.dict = DictionaryInit()
        self.metering_result = self.dict.metering_dictionary()
        self.port_mapping = self.dict.metering_ports()
    
    def measure_packet(self, packet):
        if TCP in packet:
            d_port = packet[TCP].dport
            port_sum = self.metering_buffer.get(d_port, 0)
            self.metering_buffer[d_port] = packet[IP].len + port_sum
        #Packet without TCP Layer (subsequently, without destination port)
        elif IP in packet: 
            self.metering_result['etc'] += packet[IP].len
        #Packet without IP layer
        else: 
            self.ignored_count += 1

    def calculate_and_persist(self):
        #Shallow copy dict shared by threads
        metering_result_copy = dict(self.calculate_usage())
        self.persist_metering_result(metering_result_copy)
        del metering_result_copy
        #reset values
        self.metering_result = self.dict.metering_dictionary()
        self.ignored_count = 0
        self.print_results()

    def calculate_usage(self):
        #Shallow copy dict shared by threads
        buffer_copy = dict(self.metering_buffer)
        self.metering_buffer = {}
        for port in buffer_copy:
            port_usage = buffer_copy[port] / self.aux_thread_interval
            service = self.classify_port(port)
            self.metering_result[service] += int(port_usage)
        return self.metering_result
        

    def run(self):
        self.init_persistance()
        while not self.stopped.wait(self.aux_thread_interval):
            self.calculate_and_persist()
    
    def classify_port(self, port):
        if port in self.port_mapping:
            return self.port_mapping[port]
        return 'etc'

    def start_monitoring(self):
        print("Metering link usage, interval: "+str(self.aux_thread_interval))
        self.start_sniffing()
        self.start()

    def _db_init_persistance(self, cursor):
        cursor.execute('''CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, interface VARCHAR(40), m_etc INTEGER, m_nova INTEGER, m_keystone INTEGER, m_glance INTEGER, m_cinder INTEGER, m_swift INTEGER, ignored_count INTEGER, time DATE DEFAULT (DATETIME(CURRENT_TIMESTAMP, 'LOCALTIME')) )''')

    def init_persistance(self):
        self.db.create_conn()
        self.db.wrap_access(self._db_init_persistance)

    def _db_persist_result(self, cursor, result):
        cursor.execute('''INSERT INTO link_usage (interface, ignored_count, m_cinder, m_etc, m_glance, m_keystone, m_nova, m_swift) VALUES ("{iface}", "{ignored_count}", "{cinder}", "{etc}", "{glance}", "{keystone}", "{nova}", "{swift}")'''.format(iface=self.sniff_iface, ignored_count=str(self.ignored_count), **result))

    def persist_metering_result(self, result={}):
        self.db.wrap_access(self._db_persist_result, result)

    def _db_print_results(self, cursor):
        result = cursor.execute("SELECT * FROM link_usage ORDER BY time DESC LIMIT 1")
        print(result.fetchone())
    
    def print_results(self):
        self.db.wrap_access(self._db_print_results)