# Based on code from https://askldjd.com/2014/01/15/a-reasonably-fast-python-ip-sniffer

import socket
from threading import Event
from scapy.data import ETH_P_ALL

MTU = 0xFFFF

#Socket Constant Missing in Python 3.6
SO_RCVBUFFORCE = 33


class IPSniff:

    def __init__(self, interface_name, callback=None, stop_cond: Event=Event()):

        self.interface_name = interface_name
        self.on_packet = callback
        self.stop_cond = stop_cond

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))

    def recv(self):
        if self.on_packet is None:
            raise ReferenceError('Callback function was not provided!')

        while not self.stop_cond.is_set():

            pkt, sa_ll = self.ins.recvfrom(MTU)

            self.on_packet(sa_ll[2], pkt)