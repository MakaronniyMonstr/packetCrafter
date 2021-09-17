from enum import Enum
import scapy.layers.inet as layers
import scapy.packet as packet
import scapy.all


class PacketManager:
    class PacketType(Enum):
        IP = 0
        TCP = 6
        UDP = 17
        ICMP = 1

    def __init__(self):
        pass

    @staticmethod
    def send(ip_data: {}, iface, additional_layer_data=None, additional_layer=None ):
        ip = PacketManager.build(ip_data, layers.IP)
        pckt = layers.Ether() / ip

        if additional_layer_data:
            pckt = pckt / PacketManager.build(additional_layer_data, additional_layer)
        scapy.all.sendp(pckt, iface=iface)


    @staticmethod
    def build(layer_data: {}, layer):
        return layer.__init__(**layer_data)
