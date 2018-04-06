from threading import Thread, Timer, Event
from scapy.all import sniff, Packet, TCP, IP, IPv6
import os
import time
import copy


class MonitoringModule(Thread):
    MODE_IPV4 = 0
    MODE_IPV6 = 1
    TRAFFIC_OUTBOUND = 'out'
    TRAFFIC_INBOUND = 'in'

    def __init__(self, iface='lo', filter='tcp', action=None, mode=MODE_IPV4):
        Thread.__init__(self)
        self.stopped = Event()
        self.sniff_iface = iface
        self.sniff_filter = filter
        self.sniff_thread = None
        self.action = self.default_sniff_action if action is None else action

        self.mode = mode
        if mode == MonitoringModule.MODE_IPV4:
            self.ip_layer = IP
        else:
            self.ip_layer = IPv6
        self.iface_ip = self.get_iface_ip(iface, mode)
        self.start_time = time.time()

    def default_sniff_action(self, packet):
        return

    def execution_time(self) -> int:
        return round(time.time() - self.start_time)

    def get_iface_ip(self, iface: str, mode=MODE_IPV4) -> str:
        cmd = 'ip addr show '+iface
        if mode == MonitoringModule.MODE_IPV6:
            split = "inet6 "
        else:
            split = "inet "
        return os.popen(cmd).read().split(split)[1].split("/")[0]
    
    def start_sniffing(self, args={}):
        self.sniff_thread = Thread(target=sniff, kwargs={'iface':self.sniff_iface, 'prn':self.action, 'filter':self.sniff_filter, 'store':0}, **args)
        self.sniff_thread.start()

    def stop_execution(self):
        self.stopped.set()

    def classify_packet(self, packet: Packet, port_map: dict, iface_ip: str) -> (str, str):
        traffic_type = None
        port = None

        if self.ip_layer in packet:
            if iface_ip in packet[self.ip_layer].src:
                traffic_type = MonitoringModule.TRAFFIC_OUTBOUND
            else:
                traffic_type = MonitoringModule.TRAFFIC_INBOUND
        if TCP in packet:
            #packet port is the client dport or the server sport
            if packet.sport in port_map:
                port = packet.sport
            else:
                port = packet.dport

        return port, traffic_type
        


class DictionaryInit(object):
    def __init__(self):
        self.link_metering_ports = {'nova': set([5900, 6080, 6081, 6082, 8773, 8774, 8775] + list(range(5900, 5999))),
            'keystone': set([5000, 35357]),
            'swift': set([873, 6000, 6001, 6002, 8080]),
            'glance': set([9191, 9292]),
            'cinder': set([3260, 8776]),
            'neutron': set([9696]),
            'ceilometer': set([8777])
            #'ceph': set([6800, 7300])
        }

    def metering_services(self):
        return self.link_metering_ports.keys()

    def metering_ports(self) -> dict:
        return self.invert_dictionary_relationship(self.link_metering_ports)

    def api_ports(self) -> dict:
        port_range = {'nova': set([8774]), 
              'keystone': set([5000, 35357]), 
              'swift': set([8080]),
              'glance': set([9292]),
              'cinder': set([8776]),
              'neutron': set([9696]),
              #'ceph': set([6789])
        }
        return self.invert_dictionary_relationship(port_range)

    def port_dictionary(self) -> dict:
        dictionary = {x: [] for x in self.api_ports()}
        dictionary['etc'] = []
        return dictionary

    def metering_dictionary(self) -> dict:
        services = {x: 0 for x in self.metering_services()}
        services['etc'] = 0
        services['etc_ports'] = {}
        return {MonitoringModule.TRAFFIC_INBOUND: copy.deepcopy(services), MonitoringModule.TRAFFIC_OUTBOUND: copy.deepcopy(services)}

    def metering_buffer(self) -> dict:
        return {MonitoringModule.TRAFFIC_INBOUND: {}, MonitoringModule.TRAFFIC_OUTBOUND: {}}

    def add_multiple_key_single_value(self, keys: list=[], value=None, dictionary: dict={}):
        for key in keys:
            dictionary[key] = value
    
    def invert_dictionary_relationship(self, dictionary: dict) -> dict:
        new_dict = {}
        for key in dictionary:
            for value in dictionary[key]:
                new_dict[value] = key
        return new_dict
