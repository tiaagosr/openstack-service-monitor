from threading import Thread, Timer, Event
from scapy.all import sniff, Packet, TCP
from database import DBSession

class MonitoringModule(Thread):
    def __init__(self, iface='lo', filter='tcp', action=None, dbpath=':memory:'):
        Thread.__init__(self)
        self.stopped = Event()
        self.sniff_iface = iface
        self.sniff_filter = filter
        self.sniff_thread = None
        self.action = self.default_sniff_action if action is None else action
        self.db = DBSession(dbpath)

    def default_sniff_action(self, packet):
        return
    
    def start_sniffing(self, args={}):
        self.sniff_thread = Thread(target=sniff, kwargs={'iface':self.sniff_iface, 'prn':self.action, 'filter':self.sniff_filter, 'store':0}, **args)
        #self.sniff_thread = Thread(target=sniff, kwargs={'iface':self.sniff_iface, 'prn':self.action, 'filter':self.sniff_filter, 'store':0, 'offline':'test/labp2dapi.pcap'}, **args)
        self.sniff_thread.start()

    def stop_execution(self):
        self.stopped.set()

    def packet_port(self, packet, port_map):
        if TCP not in packet:
            return None
        d_port = packet[TCP].dport
        s_port = packet[TCP].sport
        #packet port is the client dport or the server sport
        if s_port in port_map:
            port = s_port
        else:
            port = d_port
        return port
        


class DictionaryInit(object):
    def __init__(self):
        return
        
    def metering_ports(self):
        port_range = {'nova': set([5900, 6080, 6081, 6082, 8773, 8774, 8775] + list(range(5900, 5999))), 
              'keystone': set([5000, 35357]), 
              'swift': set([873, 6000, 6001, 6002, 8080]), 
              'glance': set([9191, 9292]),
              'cinder': set([3260, 8776]),
              'ceph': set([6800, 7300])}
        return self.invert_dictionary_relationship(port_range)

    def api_ports(self):
        port_range = {'nova': set([8774]), 
              'keystone': set([5000, 35357]), 
              'swift': set([8080]),
              'glance': set([9292]),
              'cinder': set([8776]),
              'neutron': set([9696]),
              'ceph': set([6789])}
        return self.invert_dictionary_relationship(port_range)

    def port_dictionary(self):
        dict = self.api_ports()
        for port in dict:
            dict[port] = []
        dict['etc'] = []
        return dict

    def metering_dictionary(self):
        return {'etc' : 0, 'nova': 0, 'keystone': 0, 'swift': 0, 'glance': 0, 'cinder': 0, 'ceph': 0, 'etc_ports' : {}}

    def add_multiple_key_single_value(self, keys=[], value=None, dict={}):
        for key in keys:
            dict[key] = value
    
    def invert_dictionary_relationship(self, dict):
        new_dict = {}
        for key in dict:
            for value in dict[key]:
                new_dict[value] = key
        return new_dict
    