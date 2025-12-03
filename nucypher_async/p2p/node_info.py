from functools import cached_property
from typing import Protocol, TypeVar

import arrow
from nucypher_core import (
    Address,
    Conditions,
    Context,
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    FleetStateChecksum,
    MetadataRequest,
    MetadataResponse,
    NodeMetadata,
    NodeMetadataPayload,
    ReencryptionRequest,
    ReencryptionResponse,
    TreasureMap,
)
from nucypher_core.umbral import Capsule, PublicKey, VerifiedCapsuleFrag

from ..base.peer_error import InvalidMessage
from ..characters.pre import DelegatorCard, RecipientCard
from ..domain import Domain
from ..drivers.identity import IdentityAddress
from ..drivers.peer import Contact, PeerClient, PeerPublicKey, SecureContact
from ..node_base import NodeRoutes


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

    def __bytes__(self) -> bytes:
        # TODO: cache it too?
        return bytes(self.metadata)

    @classmethod
    def from_bytes(cls, data: bytes) -> "NodeInfo":
        return cls(NodeMetadata.from_bytes(data))


DeserializableT_co = TypeVar("DeserializableT_co", covariant=True)


class Deserializable(Protocol[DeserializableT_co]):
    @classmethod
    def from_bytes(cls, data: bytes) -> DeserializableT_co: ...


def unwrap_bytes(
    message_bytes: bytes, cls: type[Deserializable[DeserializableT_co]]
) -> DeserializableT_co:
    try:
        message = cls.from_bytes(message_bytes)
    except ValueError as exc:
        # Should we have a different error type for message format errors on client side?
        raise InvalidMessage.for_message(cls, exc) from exc
    return message


class NodeClient:
    def __init__(self, peer_client: PeerClient):
        self._peer_client = peer_client

    async def handshake(self, contact: Contact) -> SecureContact:
        return await self._peer_client.handshake(contact)

    async def ping(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._peer_client.communicate(secure_contact, NodeRoutes.PING)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            raise InvalidMessage.for_message(str, exc) from exc

    async def exchange_node_info(
        self,
        node_info: NodeInfo,
        fleet_state_checksum: FleetStateChecksum,
        this_node_info: NodeInfo | None,
    ) -> list[NodeInfo]:
        # TODO: should `this_node_info` be narrowed down to VerifiedNodeInfo?
        request = MetadataRequest(
            fleet_state_checksum, [this_node_info.metadata] if this_node_info else []
        )
        response_bytes = await self._peer_client.communicate(
            node_info.secure_contact, NodeRoutes.NODE_METADATA, bytes(request)
        )
        response = unwrap_bytes(response_bytes, MetadataResponse)

        try:
            payload = response.verify(node_info.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise InvalidMessage(MetadataResponse, exc) from exc

        return [NodeInfo(metadata) for metadata in payload.announce_nodes]

    async def public_information(self, secure_contact: SecureContact) -> NodeInfo:
        response_bytes = await self._peer_client.communicate(
            secure_contact, NodeRoutes.PUBLIC_INFORMATION
        )
        metadata = unwrap_bytes(response_bytes, NodeMetadata)
        return NodeInfo(metadata)

    async def reencrypt(
        self,
        node_info: NodeInfo,
        capsules: list[Capsule],
        treasure_map: TreasureMap,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        conditions: Conditions | None = None,
        context: Context | None = None,
    ) -> list[VerifiedCapsuleFrag]:
        # TODO: should we narrow down `node_info` to `VerifiedNodeInfo`?
        try:
            ekfrag = treasure_map.destinations[Address(bytes(node_info.staking_provider_address))]
        except KeyError as exc:
            raise ValueError(
                f"The provided treasure map does not list node {node_info.staking_provider_address}"
            ) from exc

        request = ReencryptionRequest(
            capsules=capsules,
            hrac=treasure_map.hrac,
            encrypted_kfrag=ekfrag,
            publisher_verifying_key=treasure_map.publisher_verifying_key,
            bob_verifying_key=recipient_card.verifying_key,
            conditions=conditions,
            context=context,
        )
        response_bytes = await self._peer_client.communicate(
            node_info.secure_contact, NodeRoutes.REENCRYPT, bytes(request)
        )

        response = unwrap_bytes(response_bytes, ReencryptionResponse)

        try:
            verified_cfrags = response.verify(
                capsules=capsules,
                alice_verifying_key=delegator_card.verifying_key,
                ursula_verifying_key=node_info.verifying_key,
                policy_encrypting_key=treasure_map.policy_encrypting_key,
                bob_encrypting_key=recipient_card.encrypting_key,
            )
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise InvalidMessage(ReencryptionResponse, exc) from exc

        return verified_cfrags

    async def decrypt(
        self,
        node_info: NodeInfo,
        request: EncryptedThresholdDecryptionRequest,
    ) -> EncryptedThresholdDecryptionResponse:
        response_bytes = await self._peer_client.communicate(
            node_info.secure_contact, NodeRoutes.DECRYPT, bytes(request)
        )
        return unwrap_bytes(response_bytes, EncryptedThresholdDecryptionResponse)

    async def status(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._peer_client.communicate(secure_contact, NodeRoutes.STATUS)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            # TODO: the error contents is the HTML page with Mako traceback,
            # process it accordingly.
            raise InvalidMessage.for_message(str, exc) from exc
