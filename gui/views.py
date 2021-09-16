import tkinter as tk
from tkinter import ttk
from gui.resources import *
from gui.components import *
from utils.MetaDict import MetaDict
import gui.resources as r
import logging

import scapy.all

import scapy.layers.inet as layers

logger = logging.getLogger(__name__)


class App(tk.Frame):
    PROTOCOLS = ('IP', 'TCP', 'UDP', 'ICMP')
    PROTOCOLS_N = {'IP': 0, 'TCP': 6, 'UDP': 17, 'ICMP': 1}
    ICMP_TYPES = {
        'echo-reply': 0,
        'echo-request': 8
    }

    IP = []
    TCP = []
    UDP = []
    ICMP = []
    last_protocol = PROTOCOLS[0]

    model = {}

    def __init__(self, root):
        super().__init__(root)

        self.ip_packet = None
        self.tcp_packet = None
        self.udp_packet = None
        self.icmp_packet = None

        self.ip_data = MetaDict(layers.IP())
        self.tcp_data = MetaDict(layers.TCP())
        self.udp_data = MetaDict(layers.UDP())
        self.icmp_data = MetaDict(layers.ICMP())

        top_frame = tk.Frame(root)
        top_frame.pack(side=tk.LEFT)

        self.protocol_value = tk.StringVar(value='IP')
        self.protocol_field = ttk.Combobox(top_frame,
                                           values=self.PROTOCOLS,
                                           textvariable=self.protocol_value,
                                           width=7,
                                           state=FrameState.READONLY.value)
        # fixme
        self.protocol_value.trace('w',
                                  lambda *args: self.on_protocol_type_changed(self.protocol_value.get()))
        self.protocol_field.grid(column=0, row=0)

        # fixme
        self.version = LabeledEntry(top_frame,
                                    r.VERSION,
                                    lambda v: self.on_data_changed([self.ip_data], 'version', int(v)))
        self.version.grid(column=0, row=1)
        self.IP.append(self.version)

        # fixme
        self.ihl = LabeledEntry(top_frame,
                                r.IHL,
                                lambda v: self.on_data_changed([self.ip_data], 'ihl', int(v)))
        self.ihl.grid(column=0, row=2)
        self.IP.append(self.ihl)

        # fixme
        self.len = LabeledEntry(top_frame,
                                r.LEN,
                                lambda v: self.on_data_changed([self.ip_data], 'len', int(v)))
        self.len.grid(column=0, row=3)
        self.IP.append(self.len)

        # fixme
        self.id = LabeledEntry(top_frame,
                               r.ID,
                               lambda v: self.on_data_changed([self.ip_data], 'id', int(v)))
        self.id.grid(column=0, row=4)
        self.IP.append(self.id)

        # fixme
        self.ttl = LabeledEntry(top_frame,
                                r.TTL,
                                lambda v: self.on_data_changed([self.ip_data], 'ttl', int(v)))
        self.ttl.grid(column=0, row=5)
        self.IP.append(self.ttl)

        # fixme
        self.frag = LabeledEntry(top_frame,
                                 r.FRAG,
                                 lambda v: self.on_data_changed([self.ip_data], 'frag', int(v)))
        self.frag.grid(column=0, row=6)
        self.IP.append(self.frag)

        # fixme
        self.chksum = LabeledEntry(top_frame,
                                   r.CS_IP,
                                   lambda v: self.on_data_changed([self.ip_data], 'chksum', int(v)))
        self.chksum.grid(column=0, row=7)
        self.IP.append(self.chksum)

        # fixme
        self.chksum_tcp = LabeledEntry(top_frame,
                                       r.CS_TCP,
                                       lambda v: print(v))
        self.chksum_tcp.grid(column=0, row=8)
        self.TCP.append(self.chksum_tcp)

        # fixme
        self.chksum_udp = LabeledEntry(top_frame,
                                       r.CS_UDP,
                                       lambda v: self.on_data_changed([self.udp_data], 'chksum', int(v)))
        self.chksum_udp.grid(column=0, row=9)
        self.UDP.append(self.chksum_udp)

        # fixme
        self.chksum_icmp = LabeledEntry(top_frame,
                                        r.CS_ICMP,
                                        lambda v: self.on_data_changed([self.icmp_data], 'chksum', int(v)))
        self.chksum_icmp.grid(column=0, row=10)
        self.ICMP.append(self.chksum_icmp)

        # fixme
        self.sport = LabeledEntry(top_frame,
                                  r.SP,
                                  lambda v: self.on_data_changed([self.udp_data, self.tcp_data], 'sport', int(v)))
        self.sport.grid(column=1, row=1)
        self.TCP.append(self.sport)
        self.UDP.append(self.sport)

        # fixme
        self.dport = LabeledEntry(top_frame,
                                  r.DP,
                                  lambda v: self.on_data_changed([self.udp_data, self.tcp_data], 'dport', int(v)))
        self.dport.grid(column=1, row=2)
        self.TCP.append(self.dport)
        self.UDP.append(self.dport)

        # fixme
        self.seq = LabeledEntry(top_frame,
                                r.SEQ,
                                lambda v: self.on_data_changed([self.tcp_data, self.icmp_data], 'seq', int(v)))
        self.seq.grid(column=1, row=3)
        self.TCP.append(self.seq)
        self.ICMP.append(self.seq)

        # fixme
        self.ack = LabeledEntry(top_frame,
                                r.ACK,
                                lambda v: self.on_data_changed([self.tcp_data], 'ack', int(v)))
        self.ack.grid(column=1, row=4)
        self.TCP.append(self.ack)

        # fixme
        self.window = LabeledEntry(top_frame,
                                   r.WS,
                                   lambda v: self.on_data_changed([self.tcp_data], 'window', int(v)))
        self.window.grid(column=1, row=6)
        self.TCP.append(self.window)

        # fixme
        self.urgptr = LabeledEntry(top_frame,
                                   r.UP,
                                   lambda v: self.on_data_changed([self.tcp_data], 'urgptr', int(v)))
        self.urgptr.grid(column=1, row=7)
        self.TCP.append(self.urgptr)

        # fixme
        self.dataofs = LabeledEntry(top_frame,
                                    r.DATAOFS,
                                    lambda v: self.on_data_changed([self.tcp_data], 'dataofs', int(v)))
        self.dataofs.grid(column=1, row=8)
        self.TCP.append(self.dataofs)

        # fixme
        self.code = LabeledEntry(top_frame,
                                 r.CODE,
                                 lambda v: self.on_data_changed([self.icmp_data], 'code', int(v)))
        self.code.grid(column=1, row=9)
        self.ICMP.append(self.code)

        self.len_udp = LabeledEntry(top_frame,
                                    r.LEN_UDP,
                                    lambda v: self.on_data_changed([self.udp_data], 'len', int(v)))
        self.len_udp.grid(column=1, row=10)
        self.UDP.append(self.len_udp)

        top_middle_frame = tk.Frame(root)
        top_middle_frame.pack(side=tk.LEFT)

        # fixme
        self.flags = VerticalFlags(top_middle_frame,
                                   r.FLAGS,
                                   ['MF', 'DF', 'evil'],
                                   lambda v: self.on_data_changed([self.ip_data], 'flags', int(v)))
        self.flags.pack(side=tk.LEFT, anchor=tk.N)
        self.IP.append(self.flags)

        # fixme
        self.control = VerticalFlags(top_middle_frame,
                                     r.CONTROL_BITS,
                                     ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C', 'N'],
                                     lambda v: self.on_data_changed([self.tcp_data], 'flags', int(v)))
        self.control.pack(side=tk.LEFT, anchor=tk.N)
        self.TCP.append(self.control)

        # fixme
        self.tos = VerticalFlags(top_middle_frame,
                                 r.TOS,
                                 ['x', 'C', 'R', 'T', 'D'],
                                 lambda v: self.on_data_changed([self.ip_data], 'tos', int(v)))
        self.tos.pack(side=tk.LEFT, anchor=tk.N)
        self.IP.append(self.tos)

        # fixme
        self.reserved = VerticalFlags(top_middle_frame,
                                      r.RESERVED,
                                      ['ECE', 'CWR', 'r4', 'r3', 'r2', 'r1'],
                                      lambda v: self.on_data_changed([self.tcp_data], 'reserved', int(v)))
        self.reserved.pack(side=tk.LEFT, anchor=tk.N)
        self.TCP.append(self.reserved)

        right_top_frame = tk.Frame(root)
        right_top_frame.pack(side=tk.LEFT)

        self.type = LabeledCombobox(right_top_frame,
                                    r.TYPE,
                                    ['echo-reply', 'echo-request'],
                                    lambda v: self.on_data_changed([self.icmp_data], 'type', self.ICMP_TYPES[v]),
                                    box_width=20)
        self.type.pack(side=tk.TOP, anchor=tk.E)
        self.ICMP.append(self.type)

        interfaces = [(el.name + ':' + el.ip) for el in scapy.all.get_working_ifaces()]
        # fixme
        self.interface = LabeledCombobox(right_top_frame,
                                         r.INTERFACE,
                                         interfaces,
                                         lambda v: print(v),
                                         box_width=20)
        self.interface.pack(side=tk.TOP, anchor=tk.E)

        # fixme
        self.src = LabeledEntry(right_top_frame,
                                r.SOURCE_ADDRESS,
                                lambda v: self.on_data_changed([self.ip_data], 'src', v),
                                lbl_width=15,
                                entry_width=15)
        self.src.pack(side=tk.TOP)
        self.IP.append(self.src)

        # fixme
        self.dst = LabeledEntry(right_top_frame,
                                r.DESTINATION_ADDRESS,
                                lambda v: self.on_data_changed([self.ip_data], 'dst', v),
                                lbl_width=15,
                                entry_width=15)
        self.dst.pack(side=tk.TOP)
        self.IP.append(self.dst)

        self.send_button = tk.Button(right_top_frame,
                                     text=r.SEND,
                                     command=self.send_packet)
        self.send_button.pack(side=tk.TOP)

        self.disable_protocol_gui('TCP')
        self.disable_protocol_gui('UDP')
        self.disable_protocol_gui('ICMP')

        self.init_ip_packet()

    def on_data_changed(self, data: [{}], field, value):
        for el in data:
            if not ((isinstance(el.META, layers.TCP) and self.last_protocol == 'TCP') or
                    (isinstance(el.META, layers.UDP) and self.last_protocol == 'UDP') or
                    (isinstance(el.META, layers.ICMP) and self.last_protocol == 'ICMP') or
                    isinstance(el.META, layers.IP)):
                continue

            if value is not None or '':
                el[field] = value
            else:
                del el[field]

            layer = el.META.__class__(**el)
            layer = layer.__class__(bytes(layer))
            if not isinstance(el.META, layers.IP):
                pack = layers.IP(**self.ip_data)
                pack = pack.__class__(bytes(pack))
                layer = pack / layer.__class__(bytes(layer))
                layer = layer[el.META.__class__]

            layer.show()

            for (k, v) in layer.fields.items():
                if k not in ['proto', 'options', 'flags', 'type']:
                    resolved = self.resolve_duplicates(el.META, k)
                    gui_el = getattr(self, resolved)
                    if v is not None:
                        gui_el.set(v)
                        el[k] = v

    def resolve_duplicates(self, obj, value):
        tcp_resolver = {'chksum': 'chksum_tcp'}
        udp_resolver = {'len': 'len_udp', 'chksum': 'chksum_udp'}
        icmp_resolver = {'chksum': 'chksum_icmp'}

        try:
            if isinstance(obj, layers.TCP):
                return tcp_resolver[value]
            elif isinstance(obj, layers.UDP):
                return udp_resolver[value]
            elif isinstance(obj, layers.ICMP):
                return icmp_resolver[value]
        except Exception as e:
            pass

        return value

    def init_ip_packet(self):
        ip = layers.IP(**self.ip_data)
        ip = ip.__class__(bytes(ip))

        for (k, v) in ip.fields.items():
            if k not in ['proto', 'options', 'flags', 'type']:
                el = getattr(self, k)
                if v:
                    el.set(v)

    def on_protocol_type_changed(self, proto):
        if self.last_protocol == proto:
            return

        self.ip_data['proto'] = self.PROTOCOLS_N[proto]

        print(f'Changed {self.last_protocol} type to {proto}')
        if self.last_protocol != 'IP':
            self.disable_protocol_gui(self.last_protocol)

        print(f'{proto} gui elements are enabled')
        for el in getattr(self, proto):
            el.enable()

        self.last_protocol = proto

    def disable_protocol_gui(self, protocol):
        if protocol not in self.PROTOCOLS:
            return

        print(f'{protocol} gui elements are disabled')
        elems = getattr(self, protocol)
        for el in elems:
            el.disable()

    def send_packet(self):
        print(f'Sending packet {self.last_protocol}')
        iface = self.interface.get().split(':')[0]
        ip = layers.IP(**self.ip_data)
        ip.show()
        if self.last_protocol == 'TCP':
            packet = layers.TCP(**self.tcp_data)
            packet.show()
            scapy.all.sendp(layers.Ether() / ip / packet, iface=iface)
        elif self.last_protocol == 'UDP':
            packet = layers.UDP(**self.udp_data)
            packet.show()
            scapy.all.sendp(layers.Ether() / ip / packet, iface=iface)
        elif self.last_protocol == 'ICMP':
            packet = layers.ICMP(**self.icmp_data)
            packet = packet.__class__(bytes(packet))
            packet.show()
            scapy.all.sendp(layers.Ether() / ip / packet, iface=iface)
        else:
            scapy.all.sendp(ip, iface=iface)


class IPFrame(tk.Frame):
    class Meta:
        data = {}
        layer = layers.IP

    def __init__(self, root):
        super().__init__(root)

        entry_frame = tk.Frame(self)
        entry_frame.pack(side=tk.LEFT)

        # fixme
        self.version = LabeledEntry(entry_frame,
                                    r.VERSION,
                                    lambda v: print(v))
        self.version.grid(column=0, row=0)

        # fixme
        self.ihl = LabeledEntry(entry_frame,
                                r.IHL,
                                lambda v: print(v))
        self.ihl.grid(column=0, row=1)

        # fixme
        self.len = LabeledEntry(entry_frame,
                                r.LEN,
                                lambda v: print(v))
        self.len.grid(column=0, row=2)

        # fixme
        self.id = LabeledEntry(entry_frame,
                               r.ID,
                               lambda v: print(v))
        self.id.grid(column=0, row=3)

        # fixme
        self.ttl = LabeledEntry(entry_frame,
                                r.TTL,
                                lambda v: print(v))
        self.ttl.grid(column=0, row=4)

        # fixme
        self.frag = LabeledEntry(entry_frame,
                                 r.FRAG,
                                 lambda v: print(v))
        self.frag.grid(column=0, row=5)

        # fixme
        self.chksum = LabeledEntry(entry_frame,
                                   r.CS_IP,
                                   lambda v: print(v))
        self.chksum.grid(column=0, row=6)

        flags_frame = tk.Frame(self)
        flags_frame.pack(side=tk.LEFT)

        # fixme
        self.tos = VerticalFlags(flags_frame,
                                 r.TOS,
                                 ['x', 'C', 'R', 'T', 'D'],
                                 lambda v: print(v))
        self.tos.pack(side=tk.LEFT, anchor=tk.N)

        # fixme
        self.src = LabeledEntry(flags_frame,
                                r.SOURCE_ADDRESS,
                                lambda v: print(v),
                                lbl_width=15,
                                entry_width=15)
        self.src.pack(side=tk.TOP)

        # fixme
        self.dst = LabeledEntry(flags_frame,
                                r.DESTINATION_ADDRESS,
                                lambda v: print(v),
                                lbl_width=15,
                                entry_width=15)
        self.dst.pack(side=tk.TOP)

    def on_data_changed(self, field, value):
        if value is not None or '':
            del self.Meta.data[field]
        else:
            self.Meta.data[field] = value
