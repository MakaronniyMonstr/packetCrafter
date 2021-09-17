
class PacketAdapter:
    def __init__(self, data, layer, ip_data=None):
        self.ip_data = ip_data
        self.data = data
        self.layer = layer

    def on_data_changed(self, field, value):
        if value is not None or '':
            self.data[field] = value
        else:
            self.data.pop(field, None)
        # Ignore chksum to allow scapy compute it automatically
        self.data.pop('chksum', None)

        self.draw_layer_data()

    def draw_layer_data(self):
        layer = self.update_packet()
        layer.show()

        for (k, v) in layer.fields.items():
            if k not in ['proto', 'options']:
                gui_el = getattr(self, k)
                if v is not None:
                    gui_el.set(v)
                    # fixme Packet breaks if set all parameters manually
                    # self.data[k] = v

    """
    Scapy need spacial calls to update packet chksum, 
    this method especially computes it and return packet with all data.
    """
    def update_packet(self):
        raise NotImplementedError('update_packet() method is not implemented.')
