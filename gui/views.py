import scapy.all

import gui.resources as r
from gui.adapter import *
from gui.components import *
from utils.PacketManager import *


class App(tk.Frame):
    def __init__(self, root):
        super().__init__(root)

        self.packet_manager = PacketManager()
        self.ip = {}
        self.tcp = {}
        self.udp = {}
        self.icmp = {}
        self.proto = ''

        self.interfaces = [iface.name for iface in scapy.all.get_working_ifaces()]

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.ip_frame = IPFrame(self.notebook,
                                self.ip,
                                lambda v: self.on_protocol_type_changed(v))
        self.notebook.add(self.ip_frame, text='IP')

        self.tcp_frame = TCPFrame(self.notebook,
                                  self.tcp,
                                  self.ip)
        self.notebook.add(self.tcp_frame, text='TCP')

        self.udp_frame = UDPFrame(self.notebook,
                                  self.udp,
                                  self.ip)
        self.notebook.add(self.udp_frame, text='UDP')

        self.icmp_frame = ICMPFrame(self.notebook,
                                    self.icmp,
                                    self.ip)
        self.notebook.add(self.icmp_frame, text='ICMP')

        menu_frame = tk.Frame(self)
        menu_frame.pack(anchor=tk.N)

        self.interface = LabeledCombobox(menu_frame,
                                         r.INTERFACE,
                                         self.interfaces,
                                         lambda v: print(v))
        self.interface.pack(side=tk.TOP)

        self.send_button = tk.Button(menu_frame,
                                     text=r.SEND,
                                     command=self.send_packet)
        self.send_button.pack(side=tk.TOP)

        self.packet_list = tk.Listbox(menu_frame,
                                      selectmode=tk.BROWSE)
        self.packet_list.pack(side=tk.TOP, fill=tk.BOTH)

        self.add_button = tk.Button(menu_frame,
                                    text=r.ADD,
                                    command=lambda: (self.packet_manager.packets.append(self._prepare_packet()),
                                                     self.packet_list.insert(tk.END, next((k for (k, v) in IPFrame.PROTOCOLS.items() if k == self.proto), r.ERROR))))
        self.add_button.pack(side=tk.LEFT, anchor=tk.NW)

        self.clear_button = tk.Button(menu_frame,
                                      text=r.CLEAR,
                                      command=lambda: (self.packet_manager.packets.clear(),
                                                       self.packet_list.delete(0, tk.END)))
        self.clear_button.pack(side=tk.LEFT, anchor=tk.NE)

        self.send_all_button = tk.Button(menu_frame,
                                         text=r.SEND_ALL,
                                         command=lambda: self.packet_manager.send_all(self.interface.get()))
        self.send_all_button.pack(side=tk.LEFT, anchor=tk.N)

        # Start with IP protocol
        self.on_protocol_type_changed('IP')

    def on_protocol_type_changed(self, proto):
        if self.proto == proto:
            return

        # fixme Looks so awful. Switch should be removed
        if proto == 'IP':
            self.notebook.tab(1, state=FrameState.DISABLED.value)
            self.notebook.tab(2, state=FrameState.DISABLED.value)
            self.notebook.tab(3, state=FrameState.DISABLED.value)
        elif proto == 'TCP':
            self.notebook.tab(1, state=FrameState.NORMAL.value)
            self.notebook.tab(2, state=FrameState.DISABLED.value)
            self.notebook.tab(3, state=FrameState.DISABLED.value)
        elif proto == 'UDP':
            self.notebook.tab(1, state=FrameState.DISABLED.value)
            self.notebook.tab(2, state=FrameState.NORMAL.value)
            self.notebook.tab(3, state=FrameState.DISABLED.value)
        elif proto == 'ICMP':
            self.notebook.tab(1, state=FrameState.DISABLED.value)
            self.notebook.tab(2, state=FrameState.DISABLED.value)
            self.notebook.tab(3, state=FrameState.NORMAL.value)

        self.proto = proto

    def send_packet(self):
        print(f'Sending packet {self.proto}')
        interface = self.interface.get()
        packet = self._prepare_packet()
        scapy.all.sendp(packet, iface=interface)

    def _prepare_packet(self):
        ip = layers.IP(**self.ip)

        if self.proto == 'TCP':
            return self.packet_manager.build(ip, layers.TCP(**self.tcp))
        elif self.proto == 'UDP':
            return self.packet_manager.build(ip, layers.UDP(**self.udp))
        elif self.proto == 'ICMP':
            return self.packet_manager.build(ip, layers.ICMP(**self.icmp))
        else:
            return self.packet_manager.build(ip, None)


class IPFrame(tk.Frame, PacketAdapter):
    PROTOCOLS = {'IP': 0, 'TCP': 6, 'UDP': 17, 'ICMP': 1}

    def __init__(self, root, data, protocol_changed_handler):
        tk.Frame.__init__(self, root)
        PacketAdapter.__init__(self, data, layers.IP())

        entry_frame = tk.Frame(self)
        entry_frame.pack(side=tk.LEFT, anchor=tk.N)

        self.version = LabeledEntry(entry_frame,
                                    r.VERSION,
                                    lambda v: self.on_data_changed('version', int(v)),
                                    lbl_width=7,
                                    entry_width=15)
        self.version.grid(column=0, row=0)

        self.ihl = LabeledEntry(entry_frame,
                                r.IHL,
                                lambda v: self.on_data_changed('ihl', int(v)),
                                lbl_width=7,
                                entry_width=15)
        self.ihl.grid(column=0, row=1)

        self.len = LabeledEntry(entry_frame,
                                r.LEN,
                                lambda v: self.on_data_changed('len', int(v)),
                                lbl_width=7,
                                entry_width=15)
        self.len.grid(column=0, row=2)

        self.id = LabeledEntry(entry_frame,
                               r.ID,
                               lambda v: self.on_data_changed('id', int(v)),
                               lbl_width=7,
                               entry_width=15)
        self.id.grid(column=0, row=3)

        self.ttl = LabeledEntry(entry_frame,
                                r.TTL,
                                lambda v: self.on_data_changed('ttl', int(v)),
                                lbl_width=7,
                                entry_width=15)
        self.ttl.grid(column=0, row=4)

        self.frag = LabeledEntry(entry_frame,
                                 r.FRAG,
                                 lambda v: self.on_data_changed('frag', int(v)),
                                 lbl_width=7,
                                 entry_width=15)
        self.frag.grid(column=0, row=5)

        self.chksum = LabeledEntry(entry_frame,
                                   r.CS_IP,
                                   lambda v: self.on_data_changed('chksum', int(v)),
                                   lbl_width=7,
                                   entry_width=15)
        self.chksum.grid(column=0, row=6)

        self.src = LabeledEntry(entry_frame,
                                r.SOURCE_ADDRESS,
                                lambda v: self.on_data_changed('src', v),
                                lbl_width=7,
                                entry_width=15)
        self.src.grid(column=0, row=7)

        self.dst = LabeledEntry(entry_frame,
                                r.DESTINATION_ADDRESS,
                                lambda v: self.on_data_changed('dst', v),
                                lbl_width=7,
                                entry_width=15)
        self.dst.grid(column=0, row=8)

        flags_frame = tk.Frame(self)
        flags_frame.pack(side=tk.LEFT, anchor=tk.N)

        self.flags = VerticalFlags(flags_frame,
                                   r.FLAGS,
                                   ['MF', 'DF', 'evil'],
                                   lambda v: self.on_data_changed('flags', int(v)))
        self.flags.pack(side=tk.LEFT, anchor=tk.N)

        self.tos = VerticalFlags(flags_frame,
                                 r.TOS,
                                 ['x', 'C', 'R', 'T', 'D'],
                                 lambda v: self.on_data_changed('tos', int(v)))
        self.tos.pack(side=tk.LEFT, anchor=tk.N)

        self.proto = LabeledCombobox(flags_frame,
                                     r.PROTOCOL,
                                     list(self.PROTOCOLS.keys()),
                                     lambda v: self.on_data_changed('proto', self.PROTOCOLS[v]))
        self.proto.field.trace_add(['write'], lambda *args: protocol_changed_handler(self.proto.field.get()))
        self.proto.pack(side=tk.LEFT, anchor=tk.N)

        self.reset_input_button = tk.Button(flags_frame,
                                            text=r.RESET,
                                            command=lambda: self.reset_input())
        self.reset_input_button.pack(side=tk.LEFT, anchor=tk.N)

        self.draw_layer_data()

    def update_packet(self):
        packet = self.layer.__class__(**self.data)
        return packet.__class__(bytes(packet))


class TCPFrame(tk.Frame, PacketAdapter):
    def __init__(self, root, data, ip_data):
        tk.Frame.__init__(self, root)
        PacketAdapter.__init__(self, data, layers.TCP(), ip_data)

        entry_frame = tk.Frame(self)
        entry_frame.pack(side=tk.LEFT)

        self.sport = LabeledEntry(entry_frame,
                                  r.SP,
                                  lambda v: self.on_data_changed('sport', int(v)))
        self.sport.grid(column=0, row=0)

        self.dport = LabeledEntry(entry_frame,
                                  r.DP,
                                  lambda v: self.on_data_changed('dport', int(v)))
        self.dport.grid(column=0, row=1)

        self.seq = LabeledEntry(entry_frame,
                                r.SEQ,
                                lambda v: self.on_data_changed('seq', int(v)))
        self.seq.grid(column=0, row=3)

        self.ack = LabeledEntry(entry_frame,
                                r.ACK,
                                lambda v: self.on_data_changed('ack', int(v)))
        self.ack.grid(column=0, row=4)

        self.dataofs = LabeledEntry(entry_frame,
                                    r.DATAOFS,
                                    lambda v: self.on_data_changed('dataofs', int(v)))
        self.dataofs.grid(column=0, row=5)

        self.window = LabeledEntry(entry_frame,
                                   r.WS,
                                   lambda v: self.on_data_changed('window', int(v)))
        self.window.grid(column=0, row=6)

        self.urgptr = LabeledEntry(entry_frame,
                                   r.UP,
                                   lambda v: self.on_data_changed('urgptr', int(v)))
        self.urgptr.grid(column=0, row=7)

        self.chksum = LabeledEntry(entry_frame,
                                   r.CHK,
                                   lambda v: self.on_data_changed('chksum', int(v)))
        self.chksum.grid(column=0, row=8)

        flags_frame = tk.Frame(self)
        flags_frame.pack(side=tk.LEFT)

        self.reserved = VerticalFlags(flags_frame,
                                      r.RESERVED,
                                      ['ECE', 'CWR', 'r4', 'r3', 'r2', 'r1'],
                                      lambda v: self.on_data_changed('reserved', int(v)))
        self.reserved.pack(side=tk.LEFT, anchor=tk.N)

        self.flags = VerticalFlags(flags_frame,
                                   r.CONTROL_BITS,
                                   ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C', 'N'],
                                   lambda v: self.on_data_changed('flags', int(v)))
        self.flags.pack(side=tk.LEFT, anchor=tk.N)

        self.reset_input_button = tk.Button(flags_frame,
                                            text=r.RESET,
                                            command=lambda: self.reset_input())
        self.reset_input_button.pack(side=tk.LEFT, anchor=tk.N)

        self.draw_layer_data()

    def update_packet(self):
        pack = layers.IP(**self.ip_data) / layers.TCP(**self.data)
        layer = layers.IP(bytes(pack[layers.IP])) / layers.TCP(bytes(pack[layers.TCP]))
        return layer[layers.TCP]


class UDPFrame(tk.Frame, PacketAdapter):
    def __init__(self, root, data, ip_data):
        tk.Frame.__init__(self, root)
        PacketAdapter.__init__(self, data, layers.TCP(), ip_data)

        entry_frame = tk.Frame(self)
        entry_frame.pack(side=tk.LEFT)

        self.sport = LabeledEntry(entry_frame,
                                  r.SP,
                                  lambda v: self.on_data_changed('sport', int(v)))
        self.sport.grid(column=0, row=0)

        self.dport = LabeledEntry(entry_frame,
                                  r.DP,
                                  lambda v: self.on_data_changed('dport', int(v)))
        self.dport.grid(column=0, row=1)

        self.len = LabeledEntry(entry_frame,
                                r.LEN,
                                lambda v: self.on_data_changed('len', int(v)))
        self.len.grid(column=0, row=2)

        self.chksum = LabeledEntry(entry_frame,
                                   r.CHK,
                                   lambda v: self.on_data_changed('chksum', int(v)))
        self.chksum.grid(column=0, row=3)

        self.reset_input_button = tk.Button(entry_frame,
                                            text=r.RESET,
                                            command=lambda: self.reset_input())
        self.reset_input_button.grid(column=1, row=0)

        self.draw_layer_data()

    def update_packet(self):
        pack = layers.IP(**self.ip_data) / layers.UDP(**self.data)
        layer = layers.IP(bytes(pack[layers.IP])) / layers.UDP(bytes(pack[layers.UDP]))
        return layer[layers.UDP]


class ICMPFrame(tk.Frame, PacketAdapter):
    ICMP_TYPES = {
        'echo-request': 8,
        'echo-reply': 0
    }

    def __init__(self, root, data, ip_data):
        tk.Frame.__init__(self, root)
        PacketAdapter.__init__(self, data, layers.TCP(), ip_data)

        entry_frame = tk.Frame(self)
        entry_frame.pack(side=tk.LEFT)

        self.seq = LabeledEntry(entry_frame,
                                r.SEQ,
                                lambda v: self.on_data_changed('seq', int(v)))
        self.seq.grid(column=0, row=0)

        self.id = LabeledEntry(entry_frame,
                               r.ID,
                               lambda v: self.on_data_changed('id', int(v)))
        self.id.grid(column=0, row=1)

        self.code = LabeledEntry(entry_frame,
                                 r.CODE,
                                 lambda v: self.on_data_changed('code', int(v)))
        self.code.grid(column=0, row=2)

        self.chksum = LabeledEntry(entry_frame,
                                   r.CHK,
                                   lambda v: self.on_data_changed('chksum', int(v)))
        self.chksum.grid(column=0, row=3)

        flag_frame = tk.Frame(self)
        flag_frame.pack(side=tk.LEFT)

        self.type = LabeledCombobox(flag_frame,
                                    r.TYPE,
                                    list(self.ICMP_TYPES.keys()),
                                    lambda v: self.on_data_changed('type', self.ICMP_TYPES[v]),
                                    box_width=20)
        self.type.pack(side=tk.LEFT, anchor=tk.N)

        self.reset_input_button = tk.Button(flag_frame,
                                            text=r.RESET,
                                            command=lambda: self.reset_input())
        self.reset_input_button.pack(side=tk.LEFT, anchor=tk.N)

        self.draw_layer_data()

    def update_packet(self):
        pack = layers.IP(**self.ip_data) / layers.ICMP(**self.data)
        layer = layers.IP(bytes(pack[layers.IP])) / layers.ICMP(bytes(pack[layers.ICMP]))
        return layer[layers.ICMP]
