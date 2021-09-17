import scapy.all
import scapy.layers.inet as layers


class PacketManager:
    def __init__(self):
        self.packets = []

    def send_all(self, iface):
        for packet in self.packets:
            scapy.all.sendp(packet, iface=iface)

    @staticmethod
    def send(ip, additional_layer, iface):
        pckt = PacketManager.build(ip, additional_layer)
        scapy.all.sendp(pckt, iface=iface)

    def build(self, ip, additional_layer):
        pckt = layers.Ether() / ip
        if additional_layer:
            pckt = pckt / additional_layer
        return pckt
