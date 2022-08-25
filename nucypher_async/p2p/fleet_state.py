from typing import Iterable, Dict

from nucypher_core import NodeMetadata, FleetStateChecksum

from ..drivers.identity import IdentityAddress
from ..drivers.peer import Contact, PeerInfo
from ..verification import PublicUrsula


class FleetState:
    """
    Maintains the list of node metadata used to supply other nodes with FleetStateChecksum
    (of questionable usefulness, see https://github.com/nucypher/nucypher/issues/2876).
    """

    def __init__(self, clock, this_node: PublicUrsula):
        self._clock = clock
        self._my_metadata = this_node.metadata
        self._metadatas: Dict[IdentityAddress, PeerInfo] = {}
        self._contacts: Dict[Contact, IdentityAddress] = {}
        self._checksum = None
        self.timestamp_epoch = int(self._clock.utcnow().timestamp())

    def _add_metadata(self, metadata: PeerInfo):
        address = metadata.staking_provider_address
        contact = metadata.contact
        self._metadatas[address] = metadata
        self._contacts[contact] = address

    def add_metadatas(self, metadatas: Iterable[PeerInfo]):
        updated = False
        for metadata in metadatas:
            address = metadata.staking_provider_address
            if address not in self._metadatas or metadata.timestamp > self._metadatas[address].timestamp:
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
            self._checksum = FleetStateChecksum(
                self._my_metadata,
                [m.metadata for m in self._metadatas.values()])
            self.timestamp_epoch = int(self._clock.utcnow().timestamp())
        return self._checksum
