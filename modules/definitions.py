import socket
from datetime import datetime
from threading import Event
import multiprocessing as mp
from peewee import SqliteDatabase, Model, CharField, TimeField
from modules.sniffer import IPSniff
from scapy.layers.inet import IP, TCP, Packet
from scapy.layers.inet6 import IPv6
import os
import time


class PacketSniffer(mp.Process):

    def __init__(self, iface):
        super().__init__()
        self.conn = None
        self.iface = iface
        self.sniffer = IPSniff(self.iface, callback=self.store_packet)

    def start_sniffing(self):
        if self.conn is None:
            raise ReferenceError("Communication pipe not initialized!")
        self.start()

    def setup_connection(self):
        recv_conn, send_conn = mp.Pipe(duplex=False)
        self.conn = send_conn
        return recv_conn

    def add_filter(self, socket_filter):
        self.sniffer.add_filter(socket_filter)

    def store_packet(self, direction, packet):
        self.conn.send((direction, packet))

    def run(self):
        self.sniffer.recv()
        print("Sniffer thread Stopped!")

    def stop(self):
        self.conn.send((None, None))
        self.sniffer.ins.close()
        self.conn.close()


class MonitoringModule(mp.Process):
    MODE_IPV4 = 'inet'
    MODE_IPV6 = 'inet6'
    TRAFFIC_OUTBOUND = 'out'
    TRAFFIC_INBOUND = 'in'
    START_TIME = time.time()
    DATABASE = SqliteDatabase(None)

    @staticmethod
    def packet_type(traffic_type):
        if traffic_type == socket.PACKET_OUTGOING:
            return MonitoringModule.TRAFFIC_OUTBOUND
        return MonitoringModule.TRAFFIC_INBOUND

    def __init__(self, interface='lo', mode=MODE_IPV4, db_path='monitoring.db', session=None):
        super().__init__()
        self.stopped = Event()
        self.sniff_iface = interface
        self.sniffer = PacketSniffer(interface)
        self.conn = self.sniffer.setup_connection()
        self.db_path = db_path
        self.session = session

        self.mode = mode
        if mode == MonitoringModule.MODE_IPV4:
            self.ip_layer = IP
        else:
            self.ip_layer = IPv6
        self.iface_ip = self.iface_ip(interface, mode)

    @staticmethod
    def init_db(db_path):
        MonitoringModule.DATABASE.init(db_path)
        MonitoringModule.DATABASE.connect()
        MonitoringModule.DATABASE.create_tables([MonitoringSession])

    @staticmethod
    def create_session(interface, db_path):
        MonitoringModule.init_db(db_path)
        session = MonitoringSession.create(interface=interface)
        session.save()
        return session

    @staticmethod
    def execution_time() -> int:
        return round(time.time() - MonitoringModule.START_TIME)

    @staticmethod
    def iface_ip(iface: str, mode=MODE_IPV4) -> str:
        cmd = 'ip addr show ' + iface
        split = mode + ' '
        return os.popen(cmd).read().split(split)[1].split("/")[0]

    def start_sniffing(self):
        self.sniffer.start_sniffing()

    def stop(self):
        self.sniffer.stop()
        self.sniffer.terminate()
        self.sniffer.join()
        print('Sniffer process stopped!')

    def cleanup(self):
        self.conn.close()


    @staticmethod
    def classify_packet(packet: Packet, port_map: dict) -> str:
        port = None
        if TCP in packet:
            # packet port is the client dport or the server sport
            if packet.sport in port_map:
                port = packet.sport
            else:
                port = packet.dport

        return port


class DictTools:
    @staticmethod
    def add_multiple_key_single_value(keys: list = [], value=None, dictionary: dict = {}):
        for key in keys:
            dictionary[key] = value

    @staticmethod
    def invert(dictionary: dict) -> dict:
        new_dict = {}
        for key in dictionary:
            for value in dictionary[key]:
                new_dict[value] = key
        return new_dict


class MonitoringSession(Model):
    interface = CharField()
    executed = TimeField(formats='%H:%M:%S', default=datetime.now)

    class Meta:
        database = MonitoringModule.DATABASE

    def __init__(self, **kwargs):
        super(MonitoringSession, self).__init__(**kwargs)



