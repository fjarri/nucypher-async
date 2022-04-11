from typing import Iterable

from nucypher_core import NodeMetadata, FleetStateChecksum

from ..drivers.rest_client import Contact


class FleetState:
    """
    Maintains the list of node metadata used to supply other nodes with FleetStateChecksum
    (of questionable usefulness, see https://github.com/nucypher/nucypher/issues/2876).
    """

    def __init__(self, clock, my_metadata: NodeMetadata):
        self._clock = clock
        self._my_metadata = my_metadata
        self._metadatas = {}
        self._contacts = {}
        self._checksum = None
        self.timestamp_epoch = int(self._clock.utcnow().timestamp())

    def _add_metadata(self, metadata):
        payload = metadata.payload
        address = payload.staking_provider_address
        contact = Contact(payload.host, payload.port)

        self._metadatas[address] = metadata
        self._contacts[contact] = address

    def add_metadatas(self, metadatas: Iterable[NodeMetadata]):
        updated = False
        for metadata in metadatas:
            payload = metadata.payload
            address = payload.staking_provider_address
            if address not in self._metadatas or payload.timestamp_epoch > self._metadatas[address].payload.timestamp_epoch:
                self._add_metadata(metadata)
                updated = True

        if updated:
            self._checksum = None

    def remove_contact(self, contact: Contact):
        if contact in self._contacts:
            address = self._contacts[contact]
            del self._contacts[contact]
            del self._metadatas[address]

    @property
    def checksum(self):
        if not self._checksum:
            self._checksum = FleetStateChecksum(self._my_metadata, list(self._metadatas.values()))
            self.timestamp_epoch = int(self._clock.utcnow().timestamp())
        return self._checksum
