from scapy.all import IP, Packet, sniff, TCP, IPv6, bind_layers, Raw
from scapy_http.http import HTTP
from threading import Thread, Timer, Event
from modules.definitions import MonitoringModule, DictionaryInit

class ApiLogging(MonitoringModule):

    def __init__(self, dbpath, iface='wlp2s0', filter='tcp and (dst port 8774 or dst port 5000 or dst port 35357 or dst port 8080 or dst port 9292 or dst port 8776 or dst port 9696)', interval=10):
        super().__init__(iface, filter, self.measure_packet, dbpath)
        self.aux_thread_interval = interval
        self.dict = DictionaryInit()
        self.metering_result = self.dict.metering_dictionary()
        self.port_mapping = self.dict.api_ports()
        self.api_buffer = self.dict.port_dictionary()
        self._bind_ports_http()
        print(self.api_buffer)

    def _bind_ports_http(self):
        for port in self.port_mapping:
            bind_layers(TCP, HTTP, sport=port)
            bind_layers(TCP, HTTP, dport=port)

    def measure_packet(self, packet):
        if IP in packet:
            IP_layer = IP
        elif IPv6 in packet:
            IP_layer = IPv6
        else:
            return

        if packet.haslayer('Raw'):
            dport = packet[TCP].dport
            self.api_buffer[dport].append(packet[Raw].load)
        return packet.show()

    def computate_and_persist(self):
        print(self.api_buffer)
        for port in self.api_buffer:
            tmp_list = list(self.api_buffer[port])
            self.api_buffer[port] = []
            for entry in tmp_list:
                print("Destiny: "+port)
    
    def classify_port(self, port):
        if port in self.port_mapping:
            return self.port_mapping[port]
        return 'etc'

    def run(self):
        #self.init_persistance()
        while not self.stopped.wait(self.aux_thread_interval):
            self.computate_and_persist()

    def start_monitoring(self):
        print("Logging API requests")
        self.start_sniffing({})
        self.start()

    def _db_init_persistance(self, cursor):
        cursor.execute('''CREATE TABLE IF NOT EXISTS link_usage(id INTEGER PRIMARY KEY, interface VARCHAR(40), m_etc INTEGER, m_nova INTEGER, m_keystone INTEGER, m_glance INTEGER, m_cinder INTEGER, m_swift INTEGER, ignored_count INTEGER, time DATE DEFAULT (DATETIME(CURRENT_TIMESTAMP, 'LOCALTIME')) )''')

    def init_persistance(self):
        self.db.create_conn()
        self.db.wrap_access(self._db_init_persistance)