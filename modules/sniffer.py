# Based on code from https://askldjd.com/2014/01/15/a-reasonably-fast-python-ip-sniffer

import socket
import ctypes
from threading import Event
from scapy.data import ETH_P_ALL

MTU = 0xFFFF

#Socket Constant Missing in Python 3.6
SO_RCVBUFFORCE = 33
SO_ATTACH_FILTER = 26


class BpfProgram(ctypes.Structure):
    _fields_ = [
        ('bf_len', ctypes.c_int),
        ('bf_insns', ctypes.c_void_p)
    ]


class BpfInstruction(ctypes.Structure):
    _fields_ = [
        ('code', ctypes.c_uint16),
        ('jt', ctypes.c_uint8),
        ('jf', ctypes.c_uint8),
        ('k', ctypes.c_uint32),
    ]

# REGEX
# FROM \{ (.+) \}
# TO \[$1\]
DEFAULT_FILTER = [
    [0x28, 0, 0, 0x0000000c],
    [0x15, 0, 5, 0x000086dd],
    [0x30, 0, 0, 0x00000014],
    [0x15, 6, 0, 0x00000006],
    [0x15, 0, 34, 0x0000002c],
    [0x30, 0, 0, 0x00000036],
    [0x15, 3, 32, 0x00000006],
    [0x15, 0, 31, 0x00000800],
    [0x30, 0, 0, 0x00000017],
    [0x15, 0, 29, 0x00000006],
    [0x28, 0, 0, 0xfffff004],
    [0x15, 27, 0, 0x00000004],
    [0x28, 0, 0, 0x0000000c],
    [0x15, 0, 6, 0x000086dd],
    [0x30, 0, 0, 0x00000014],
    [0x15, 2, 0, 0x00000084],
    [0x15, 1, 0, 0x00000006],
    [0x15, 0, 21, 0x00000011],
    [0x28, 0, 0, 0x00000038],
    [0x15, 18, 10, 0x00002246],
    [0x15, 0, 18, 0x00000800],
    [0x30, 0, 0, 0x00000017],
    [0x15, 2, 0, 0x00000084],
    [0x15, 1, 0, 0x00000006],
    [0x15, 0, 14, 0x00000011],
    [0x28, 0, 0, 0x00000014],
    [0x45, 12, 0, 0x00001fff],
    [0xb1, 0, 0, 0x0000000e],
    [0x48, 0, 0, 0x00000010],
    [0x15, 8, 0, 0x00002246],
    [0x15, 7, 0, 0x00001388],
    [0x15, 6, 0, 0x00008a1d],
    [0x15, 5, 0, 0x00001f90],
    [0x15, 4, 0, 0x0000244c],
    [0x15, 3, 0, 0x00002248],
    [0x15, 2, 0, 0x000025e0],
    [0x15, 1, 0, 0x00001a85],
    [0x15, 0, 1, 0x00000050],
    [0x6, 0, 0, 0x00040000],
    [0x6, 0, 0, 0x00000000],
]


def attach_reject_filter(sock, sock_filter):
    insns = (BpfInstruction * len(sock_filter))()
    for i, (code, jt, jf, k) in enumerate(sock_filter):
        insns[i].code = code
        insns[i].jt = jt
        insns[i].jf = jf
        insns[i].k = k

    prog = BpfProgram()
    prog.bf_len = len(sock_filter)  # Opcode count
    prog.bf_insns = ctypes.addressof(insns)

    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(prog))


class IPSniff:

    def __init__(self, interface_name, stop_cond: Event=Event(), callback=None):

        self.interface_name = interface_name
        self.on_packet = callback
        self.stop_cond = stop_cond

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))

    def add_filter(self, bpf=DEFAULT_FILTER):
        if self.ins is None:
            raise AttributeError('Socket was not initialized')
        attach_reject_filter(self.ins, bpf)

    def recv(self):
        if self.on_packet is None:
            raise ReferenceError('Callback function missing!')

        while True:
            pkt, sa_ll = self.ins.recvfrom(MTU)
            self.on_packet(sa_ll[2], pkt)