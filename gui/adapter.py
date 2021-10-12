class PacketAdapter:
    def __init__(self, data, layer, ip_data=None):
        self.ip_data = ip_data
        self.data = data
        self.layer = layer

    """
    On gui data changed listener.
    :field field name in internet layer
    :value field value in internet layer
    """
    def on_data_changed(self, field, value):
        if value is not None or '':
            self.data[field] = value
        else:
            self.data.pop(field, None)

        self.draw_layer_data()

    """
    Draw all data to gui.
    """
    def draw_layer_data(self):
        layer = self.update_packet()
        layer.show()

        for (k, v) in layer.fields.items():
            if k not in ['proto', 'options', 'payload', 'unused']:
                gui_el = getattr(self, k)
                if v is not None:
                    gui_el.set(v)

    """
    Clear all input to set data to default values.
    """
    def reset_input(self):
        self.data.clear()
        self.draw_layer_data()

    """
    Scapy need spacial calls to update packet chksum, 
    this method especially computes it and return packet with all data.
    """
    def update_packet(self):
        raise NotImplementedError('update_packet() method is not implemented.')
