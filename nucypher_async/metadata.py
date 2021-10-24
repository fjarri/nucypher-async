class Metadata:

    def __init__(self, id, address):
        self.id = str(id)
        self.address = address

    def to_json(self):
        return {'id': self.id, 'address': self.address}

    @classmethod
    def from_json(cls, data):
        return cls(**data)


class FleetState:

    def __init__(self, nodes):
        self.nodes = nodes

    def to_json(self):
        return {id: metadata.to_json() for id, metadata in self.nodes.items()}

    @classmethod
    def from_json(cls, data):
        return cls({id: Metadata.from_json(metadata_json) for id, metadata_json in data.items()})

