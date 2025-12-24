from collections.abc import Iterable
from typing import TYPE_CHECKING

from nucypher_core import FleetStateChecksum

from .._drivers.time import BaseClock
from ._keys import Contact
from ._node_info import NodeInfo
from ._verification import VerifiedNodeInfo

if TYPE_CHECKING:  # pragma: no cover
    from ..blockchain.identity import IdentityAddress


class FleetState:
    """
    Maintains the list of node metadata used to supply other nodes with FleetStateChecksum
    (of questionable usefulness, see https://github.com/nucypher/nucypher/issues/2876).
    """

    def __init__(self, clock: BaseClock, this_node: VerifiedNodeInfo | None):
        self._clock = clock
        self._metadatas: dict[IdentityAddress, NodeInfo] = {}
        self._contacts: dict[Contact, IdentityAddress] = {}
        self._checksum: FleetStateChecksum | None = None
        self.timestamp_epoch = int(self._clock.utcnow().timestamp())
        if this_node is not None:
            self.add_metadatas([this_node])

    def _add_metadata(self, metadata: NodeInfo) -> None:
        address = metadata.staking_provider_address
        contact = metadata.contact
        self._metadatas[address] = metadata
        self._contacts[contact] = address

    def add_metadatas(self, metadatas: Iterable[NodeInfo]) -> None:
        updated = False
        for metadata in metadatas:
            address = metadata.staking_provider_address

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
                [m.metadata for m in self._metadatas.values()],
                None,
            )
            self.timestamp_epoch = int(self._clock.utcnow().timestamp())
        return self._checksum
