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

    def update(self, nodes_to_add: Iterable[NodeMetadata]):
        updated = False
        for metadata in nodes_to_add:
            payload = metadata.payload
            address = payload.staker_address
            if address not in self._metadatas or payload.timestamp_epoch > self._metadatas[address].payload.timestamp_epoch:
                self._metadatas[address] = metadata
                updated = True

        if updated:
            self._checksum = None

    @property
    def checksum(self):
        if not self._checksum:
            self._checksum = FleetStateChecksum(self._my_metadata, list(self._metadatas.values()))
            self.timestamp = maya.now()
        return self._checksum
