from functools import cached_property
from typing import TypeVar, Type, Protocol

import arrow
from nucypher_core import (
    NodeMetadata,
    MetadataRequest,
    MetadataResponse,
    ReencryptionRequest,
    ReencryptionResponse,
    NodeMetadataPayload,
)
from nucypher_core.umbral import PublicKey

from ..base.peer import InvalidMessage
from ..domain import Domain
from ..drivers.peer import Contact, SecureContact, PeerPublicKey, PeerClient
from ..drivers.identity import IdentityAddress


class UrsulaInfo:
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

    def __bytes__(self) -> bytes:
        # TODO: cache it too?
        return bytes(self.metadata)

    @classmethod
    def from_bytes(cls, data: bytes) -> "UrsulaInfo":
        return cls(NodeMetadata.from_bytes(data))


DeserializableT_co = TypeVar("DeserializableT_co", covariant=True)


class Deserializable(Protocol[DeserializableT_co]):
    @classmethod
    def from_bytes(cls, data: bytes) -> DeserializableT_co:
        ...


def unwrap_bytes(
    message_bytes: bytes, cls: Type[Deserializable[DeserializableT_co]]
) -> DeserializableT_co:
    try:
        message = cls.from_bytes(message_bytes)
    except ValueError as exc:
        # Should we have a different error type for message format errors on client side?
        raise InvalidMessage.for_message(cls, exc) from exc
    return message


class UrsulaClient(PeerClient):
    def __init__(self, peer_client: PeerClient):
        self._peer_client = peer_client

    async def handshake(self, contact: Contact) -> SecureContact:
        return await self._peer_client.handshake(contact)

    async def ping(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._peer_client.communicate(secure_contact, "ping")
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            raise InvalidMessage.for_message(str, exc)

    async def node_metadata_get(self, secure_contact: SecureContact) -> MetadataResponse:
        response_bytes = await self._peer_client.communicate(secure_contact, "node_metadata")
        return unwrap_bytes(response_bytes, MetadataResponse)

    async def node_metadata_post(
        self, secure_contact: SecureContact, metadata_request: MetadataRequest
    ) -> MetadataResponse:
        response_bytes = await self._peer_client.communicate(
            secure_contact, "node_metadata", bytes(metadata_request)
        )
        return unwrap_bytes(response_bytes, MetadataResponse)

    async def public_information(self, secure_contact: SecureContact) -> NodeMetadata:
        response_bytes = await self._peer_client.communicate(secure_contact, "public_information")
        return unwrap_bytes(response_bytes, NodeMetadata)

    async def reencrypt(
        self, secure_contact: SecureContact, reencryption_request: ReencryptionRequest
    ) -> ReencryptionResponse:
        response_bytes = await self._peer_client.communicate(
            secure_contact, "reencrypt", bytes(reencryption_request)
        )
        return unwrap_bytes(response_bytes, ReencryptionResponse)
