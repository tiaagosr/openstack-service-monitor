from datetime import datetime
import multiprocessing as mp
from peewee import SqliteDatabase, Model, CharField, TimeField
from scapy.layers.inet import TCP, Packet
import time
import math


class PcapAnalysisModule(mp.Process):
    START_TIME = time.time()
    DATABASE = SqliteDatabase(None)

    def __init__(self, db_path='monitoring.db', session=None, pcap: list=None):
        super().__init__()
        self.pcap = pcap
        self.db_path = db_path
        self.session = session

    @staticmethod
    def difference_in_secs(a, b):
        if a is None or b is None:
            return 0
        return abs(int(math.floor((b - a).total_seconds())))

    @staticmethod
    def init_db(db_path):
        PcapAnalysisModule.DATABASE.init(db_path)
        PcapAnalysisModule.DATABASE.connect()
        PcapAnalysisModule.DATABASE.create_tables([MonitoringSession])

    @staticmethod
    def create_session(interface, db_path):
        PcapAnalysisModule.init_db(db_path)
        session = MonitoringSession.create(interface=interface)
        session.save()
        return session

    @staticmethod
    def execution_time() -> int:
        return round(time.time() - PcapAnalysisModule.START_TIME)

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
        database = PcapAnalysisModule.DATABASE

    def __init__(self, **kwargs):
        super(MonitoringSession, self).__init__(**kwargs)



