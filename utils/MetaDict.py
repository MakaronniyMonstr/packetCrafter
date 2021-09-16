class MetaDict(dict):
    def __init__(self, meta):
        super().__init__()
        self.META = meta