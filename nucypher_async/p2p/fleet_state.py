from typing import Iterable

import maya

from nucypher_core import NodeMetadata, FleetStateChecksum


class FleetState:
    """
    Maintains the list of node metadata used to supply other nodes with FleetStateChecksum
    (of questionable usefulness, see https://github.com/nucypher/nucypher/issues/2876).
    """

    def __init__(self, my_metadata: NodeMetadata):
        self._my_metadata = my_metadata
        self._metadatas = {}
        self._checksum = None
        self.timestamp = maya.now()

    def add_metadatas(self, metadatas: Iterable[NodeMetadata]):
        updated = False
        for metadata in metadatas:
            payload = metadata.payload
            address = payload.staking_provider_address
            if address not in self._metadatas or payload.timestamp_epoch > self._metadatas[address].payload.timestamp_epoch:
                self._metadatas[address] = metadata
                updated = True

        if updated:
            self._checksum = None

    def remove_metadata(self, metadata: NodeMetadata):
        address = metadata.payload.staker_address
        if address in self._metadatas:
            if bytes(self._metadatas[address]) == bytes(metadata):
                del self._metadatas[address]

    @property
    def checksum(self):
        if not self._checksum:
            self._checksum = FleetStateChecksum(self._my_metadata, list(self._metadatas.values()))
            self.timestamp = maya.now()
        return self._checksum
