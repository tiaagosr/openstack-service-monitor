from scapy.all import IP, Packet, sniff, TCP, IPv6
from threading import Thread, Timer, Event
from modules.definitions import MonitoringModule, DictionaryInit

class ApiLogging(MonitoringModule):

    def __init__(self, db, iface='wlp2s0', filter='tcp and (portrange 8773-8777 or port 5000 or port 9292 or port 80)', interval=10):
        super().__init__(iface, filter, self.measure_packet, db)
        self.aux_thread_interval = interval
        self.dict = DictionaryInit()
        self.metering_result = self.dict.metering_dictionary()
        self.port_mapping = self.dict.api_ports()
        self.api_buffer = self.dict.port_dictionary()
        self.init_persistance()

    def measure_packet(self, packet):
        if IP in packet:
            IP_layer = IP
        elif IPv6 in packet:
            IP_layer = IPv6
        else:
            return

        if packet.haslayer('HTTP') and packet.haslayer('Raw'):
            dport = self.classify_port(packet[TCP].dport)
            self.api_buffer[dport].append(packet[Raw].load)

    def computate_and_persist(self):
        return
    
    def classify_port(self, port):
        if port in self.port_mapping:
            return self.port_mapping[port]
        return 'etc'

    def run(self):
        while not self.stopped.wait(self.aux_thread_interval):
            self.computate_and_persist()

    def start_monitoring(self):
        print("Metering link usage, interval: "+str(self.aux_thread_interval))
        self.start_sniffing({'offline':'test/testApi.pcap'})
        self.start()

    def _db_init_persistance(self, cursor):
        cursor.execute('''CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, interface VARCHAR(40), m_etc INTEGER, m_nova INTEGER, m_keystone INTEGER, m_glance INTEGER, m_cinder INTEGER, m_swift INTEGER, ignored_count INTEGER, time DATE DEFAULT (DATETIME(CURRENT_TIMESTAMP, 'LOCALTIME')) )''')

    def init_persistance(self):
        self.db.wrap_access(self._db_init_persistance)