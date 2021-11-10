import os
from typing import Dict, Set
import pickle

from .utils import Contact, SSLContact


# A temporary mixin to avoid writing down all the JSON serialization
class JsonViaPickle:

    def to_json(self):
        return pickle.dumps(self).hex()

    @classmethod
    def from_json(cls, data):
        return pickle.loads(bytes.fromhex(data))


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

    def __repr__(self):
        return f"NodeID({self._id_bytes.hex()})"

    def to_json(self):
        return self._id_bytes.hex()

    @classmethod
    def from_json(cls, data):
        return cls(bytes.fromhex(data))


class Metadata(JsonViaPickle):

    def __init__(self, node_id: NodeID, ssl_contact: SSLContact):
        self.node_id = node_id
        self.ssl_contact = ssl_contact

    def __eq__(self, other):
        return self.node_id == other.node_id and self.ssl_contact == other.ssl_contact

    @property
    def signed_contact(self):
        return SignedContact(self.ssl_contact.contact, self.node_id)


class SignedContact(JsonViaPickle):

    def __init__(self, contact: Contact, node_id: NodeID):
        self.contact = contact
        self.node_id = node_id

        # TODO: add a timestamp
        # TODO: if additional protection from generating contacts with future timestamps is necessary,
        # we can include the current Eth block hash or something

    def __repr__(self):
        return f"SignedContact({repr(self.contact)}, {repr(self.node_id)})"


class ContactRequest(JsonViaPickle):

    def __init__(self, signed_contact: SignedContact):
        self.signed_contact = signed_contact


class ContactPackage(JsonViaPickle):

    def __init__(self, metadata, contacts):
        self.contacts = contacts
        self.metadata = metadata
