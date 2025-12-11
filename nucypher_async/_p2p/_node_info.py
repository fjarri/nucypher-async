from functools import cached_property

import arrow
from nucypher_core import NodeMetadata, NodeMetadataPayload
from nucypher_core.umbral import PublicKey

from ..blockchain.identity import IdentityAddress
from ..domain import Domain
from ._keys import Contact, PeerPublicKey, SecureContact


class NodeInfo:
    def __init__(self, metadata: NodeMetadata):
        self.metadata = metadata

    @cached_property
    def _metadata_payload(self) -> NodeMetadataPayload:
        # making it a cached property since it has to create and populate new object
        # from a Rust extension, which takes some time.
        return self.metadata.payload

    @cached_property
    def contact(self) -> Contact:
        payload = self._metadata_payload
        return Contact(payload.host, payload.port)

    @cached_property
    def secure_contact(self) -> SecureContact:
        return SecureContact(self.contact, self.public_key)

    @cached_property
    def operator_address(self) -> IdentityAddress:
        return IdentityAddress(bytes(self._metadata_payload.derive_operator_address()))

    @cached_property
    def staking_provider_address(self) -> IdentityAddress:
        return IdentityAddress(bytes(self._metadata_payload.staking_provider_address))

    @cached_property
    def public_key(self) -> PeerPublicKey:
        return PeerPublicKey.from_bytes(self._metadata_payload.certificate_der)

    @cached_property
    def domain(self) -> Domain:
        return Domain(self._metadata_payload.domain)

    @property
    def encrypting_key(self) -> PublicKey:
        return self._metadata_payload.encrypting_key

    @property
    def verifying_key(self) -> PublicKey:
        return self._metadata_payload.verifying_key

    @cached_property
    def timestamp(self) -> arrow.Arrow:
        return arrow.get(self._metadata_payload.timestamp_epoch)

    @cached_property
    def _bytes(self) -> bytes:
        # Cannot apply `cached_property` to `__bytes__()` directly, so have to use a trampoline.
        return bytes(self.metadata)

    def __bytes__(self) -> bytes:
        return self._bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "NodeInfo":
        return cls(NodeMetadata.from_bytes(data))
