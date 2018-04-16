# Based on code from https://askldjd.com/2014/01/15/a-reasonably-fast-python-ip-sniffer

import socket, struct, os, array
from threading import Event
from scapy.layers.l2 import Ether
from scapy.all import ETH_P_ALL, select, MTU


class IPSniff:

    def __init__(self, interface_name, callback=None, stop_cond: Event=Event()):

        self.interface_name = interface_name
        self.on_packet = callback
        self.stop_cond = stop_cond

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))

    def recv(self):
        while not self.stop_cond.is_set():

            pkt, sa_ll = self.ins.recvfrom(MTU)

            if self.on_packet is None:
                break

            self.on_packet(sa_ll[2], pkt)