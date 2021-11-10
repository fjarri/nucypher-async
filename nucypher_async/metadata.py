from typing import NamedTuple
import os

from .certificate import SSLCertificate


class NodeID:

    @classmethod
    def random(cls):
        return cls(os.urandom(4))

    def __init__(self, id_bytes: bytes):
        assert len(id_bytes) == 4
        self._id_bytes = id_bytes

    def __eq__(self, other):
        return self._id_bytes == other._id_bytes

    def __hash__(self):
        return hash((self.__class__, self._id_bytes))

    def to_json(self):
        return self._id_bytes.hex()

    @classmethod
    def from_json(cls, data):
        return cls(bytes.fromhex(data))


class ConnectionInfo(NamedTuple):
    host: str
    port: int
    certificate: SSLCertificate

    @property
    def url(self):
        return f"https://{host}:{port}"


class Metadata:

    def __init__(self, id: NodeID, host: str, port: int, certificate: SSLCertificate):

        assert certificate.declared_host == host

        self.id = id
        self.host = host
        self.port = port
        self.certificate = certificate

    @property
    def connection_info(self):
        return ConnectionInfo(self.host, self.port, self.certificate)

    def to_json(self):
        return dict(
            id=self.id.to_json(),
            host=self.host,
            port=self.port,
            certificate=self.certificate.to_json())

    @classmethod
    def from_json(cls, data):
        return cls(
            id=NodeID.from_json(data['id']),
            host=data['host'],
            port=data['port'],
            certificate=SSLCertificate.from_json(data['certificate']))


class FleetState:

    def __init__(self, nodes):
        self.nodes = nodes

    def to_json(self):
        return {id: metadata.to_json() for id, metadata in self.nodes.items()}

    @classmethod
    def from_json(cls, data):
        return cls({id: Metadata.from_json(metadata_json) for id, metadata_json in data.items()})

