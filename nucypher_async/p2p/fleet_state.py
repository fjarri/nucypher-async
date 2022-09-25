from typing import Iterable, Dict, Optional

from nucypher_core import FleetStateChecksum

from ..base.time import BaseClock
from ..drivers.identity import IdentityAddress
from ..drivers.peer import Contact, UrsulaInfo
from .verification import PublicUrsula


class FleetState:
    """
    Maintains the list of node metadata used to supply other nodes with FleetStateChecksum
    (of questionable usefulness, see https://github.com/nucypher/nucypher/issues/2876).
    """

    def __init__(self, clock: BaseClock, this_node: Optional[PublicUrsula]):
        self._clock = clock
        self._my_address = this_node.staking_provider_address if this_node else None
        self._my_metadata = this_node.metadata if this_node else None
        self._metadatas: Dict[IdentityAddress, UrsulaInfo] = {}
        self._contacts: Dict[Contact, IdentityAddress] = {}
        self._checksum: Optional[FleetStateChecksum] = None
        self.timestamp_epoch = int(self._clock.utcnow().timestamp())

    def _add_metadata(self, metadata: UrsulaInfo) -> None:
        address = metadata.staking_provider_address
        contact = metadata.contact
        self._metadatas[address] = metadata
        self._contacts[contact] = address

    def add_metadatas(self, metadatas: Iterable[UrsulaInfo]) -> None:
        updated = False
        for metadata in metadatas:
            address = metadata.staking_provider_address
            if self._my_address and address == self._my_address:
                continue

            if (
                address not in self._metadatas
                or metadata.timestamp > self._metadatas[address].timestamp
            ):
                self._add_metadata(metadata)
                updated = True

        if updated:
            self._checksum = None

    def remove_contact(self, contact: Contact) -> None:
        if contact in self._contacts:
            address = self._contacts[contact]
            del self._contacts[contact]
            del self._metadatas[address]

    @property
    def checksum(self) -> FleetStateChecksum:
        if not self._checksum:
            self._checksum = FleetStateChecksum(
                self._my_metadata, [m.metadata for m in self._metadatas.values()]
            )
            self.timestamp_epoch = int(self._clock.utcnow().timestamp())
        return self._checksum
