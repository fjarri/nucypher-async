from functools import cached_property
from typing import TypeVar, Type, Protocol, List

import arrow
from nucypher_core import (
    NodeMetadata,
    MetadataRequest,
    MetadataResponse,
    ReencryptionRequest,
    ReencryptionResponse,
    NodeMetadataPayload,
    FleetStateChecksum,
    TreasureMap,
    Address,
)
from nucypher_core.umbral import PublicKey, Capsule, VerifiedCapsuleFrag

from ..base.peer_error import InvalidMessage
from ..base.ursula import UrsulaRoutes
from ..characters.pre import DelegatorCard, RecipientCard
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


class UrsulaClient:
    def __init__(self, peer_client: PeerClient):
        self._peer_client = peer_client

    async def handshake(self, contact: Contact) -> SecureContact:
        return await self._peer_client.handshake(contact)

    async def ping(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._peer_client.communicate(secure_contact, UrsulaRoutes.PING)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            raise InvalidMessage.for_message(str, exc)

    async def get_ursulas_info(
        self,
        ursula: UrsulaInfo,
    ) -> List[UrsulaInfo]:
        response_bytes = await self._peer_client.communicate(
            ursula.secure_contact, UrsulaRoutes.NODE_METADATA
        )
        response = unwrap_bytes(response_bytes, MetadataResponse)

        try:
            payload = response.verify(ursula.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise InvalidMessage(MetadataResponse, exc) from exc

        return [UrsulaInfo(metadata) for metadata in payload.announce_nodes]

    async def exchange_ursulas_info(
        self,
        ursula: UrsulaInfo,
        fleet_state_checksum: FleetStateChecksum,
        this_ursula: UrsulaInfo,
    ) -> List[UrsulaInfo]:
        # TODO: should `this_ursula` be narrowed down to VerifiedUrsulaInfo?
        request = MetadataRequest(fleet_state_checksum, [this_ursula.metadata])
        response_bytes = await self._peer_client.communicate(
            ursula.secure_contact, UrsulaRoutes.NODE_METADATA, bytes(request)
        )
        response = unwrap_bytes(response_bytes, MetadataResponse)

        try:
            payload = response.verify(ursula.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise InvalidMessage(MetadataResponse, exc) from exc

        return [UrsulaInfo(metadata) for metadata in payload.announce_nodes]

    async def public_information(self, secure_contact: SecureContact) -> UrsulaInfo:
        response_bytes = await self._peer_client.communicate(
            secure_contact, UrsulaRoutes.PUBLIC_INFORMATION
        )
        metadata = unwrap_bytes(response_bytes, NodeMetadata)
        return UrsulaInfo(metadata)

    async def reencrypt(
        self,
        ursula: UrsulaInfo,
        capsules: List[Capsule],
        treasure_map: TreasureMap,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
    ) -> List[VerifiedCapsuleFrag]:
        # TODO: should we narrow down `ursula` to `VerifiedUrsulaInfo`?
        try:
            ekfrag = treasure_map.destinations[Address(bytes(ursula.staking_provider_address))]
        except KeyError as exc:
            raise ValueError(
                f"The provided treasure map does not list Ursula {ursula.staking_provider_address}"
            )

        request = ReencryptionRequest(
            capsules=capsules,
            hrac=treasure_map.hrac,
            encrypted_kfrag=ekfrag,
            publisher_verifying_key=treasure_map.publisher_verifying_key,
            bob_verifying_key=recipient_card.verifying_key,
            conditions=None,
            context=None,
        )
        response_bytes = await self._peer_client.communicate(
            ursula.secure_contact, UrsulaRoutes.REENCRYPT, bytes(request)
        )

        response = unwrap_bytes(response_bytes, ReencryptionResponse)

        try:
            verified_cfrags = response.verify(
                capsules=capsules,
                alice_verifying_key=delegator_card.verifying_key,
                ursula_verifying_key=ursula.verifying_key,
                policy_encrypting_key=treasure_map.policy_encrypting_key,
                bob_encrypting_key=recipient_card.encrypting_key,
            )
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise InvalidMessage(ReencryptionResponse, exc) from exc

        return verified_cfrags

    async def status(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._peer_client.communicate(secure_contact, UrsulaRoutes.STATUS)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            # TODO: the error contents is the HTML page with Mako traceback,
            # process it accordingly.
            raise InvalidMessage.for_message(str, exc)
