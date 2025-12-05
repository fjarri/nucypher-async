import http
from typing import Protocol, TypeVar

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
    ReencryptionRequest,
    ReencryptionResponse,
    TreasureMap,
)
from nucypher_core.umbral import Capsule, VerifiedCapsuleFrag

from ..characters.pre import DelegatorCard, RecipientCard
from ..drivers.http_client import HTTPClient
from .errors import PeerError
from .keys import Contact, PeerPublicKey, SecureContact
from .node_info import NodeInfo
from .routes import NodeRoutes
from .verification import VerifiedNodeInfo


class PeerConnectionError(Exception):
    pass


DeserializableT_co = TypeVar("DeserializableT_co", covariant=True)


class Deserializable(Protocol[DeserializableT_co]):
    @classmethod
    def from_bytes(cls, data: bytes) -> DeserializableT_co: ...


def try_deserialize(
    message_bytes: bytes, cls: type[Deserializable[DeserializableT_co]]
) -> DeserializableT_co:
    try:
        message = cls.from_bytes(message_bytes)
    except ValueError as exc:
        # Should we have a different error type for message format errors on client side?
        raise PeerError.invalid_message(cls, exc) from exc
    return message


class NodeClient:
    def __init__(self, http_client: HTTPClient):
        self._http_client = http_client

    async def _http_communicate(
        self, secure_contact: SecureContact, route: str, data: bytes | None = None
    ) -> bytes:
        """Sends an optional message to the specified route and returns the response bytes."""
        path = f"{secure_contact._uri}/{route}"  # noqa: SLF001
        certificate = secure_contact.public_key._as_ssl_certificate()  # noqa: SLF001
        async with self._http_client.session(certificate) as session:
            if data is None:
                response = await session.get(path)
            else:
                response = await session.post(path, data)

        if response.status_code != http.HTTPStatus.OK:
            raise PeerError.from_bytes(response.body_bytes)
        return response.body_bytes

    async def handshake(self, contact: Contact) -> SecureContact:
        try:
            certificate = await self._http_client.fetch_certificate(contact.host, contact.port)
        except RuntimeError as exc:
            raise PeerConnectionError(str(exc)) from exc

        public_key = PeerPublicKey(certificate)
        try:
            return SecureContact(contact, public_key)
        except ValueError as exc:
            raise PeerConnectionError(str(exc)) from exc

    async def ping(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._http_communicate(secure_contact, NodeRoutes.PING)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            raise PeerError.invalid_message(str, exc) from exc

    async def exchange_node_info(
        self,
        node_info: VerifiedNodeInfo,
        fleet_state_checksum: FleetStateChecksum,
        this_node_info: NodeInfo | None,
    ) -> list[NodeInfo]:
        request = MetadataRequest(
            fleet_state_checksum, [this_node_info.metadata] if this_node_info else []
        )
        response_bytes = await self._http_communicate(
            node_info.secure_contact, NodeRoutes.NODE_METADATA, bytes(request)
        )
        response = try_deserialize(response_bytes, MetadataResponse)

        try:
            payload = response.verify(node_info.verifying_key)
        except Exception as exc:  # TODO: can we narrow it down?
            # TODO: should it be a separate error class?
            raise PeerError.invalid_message(MetadataResponse, exc) from exc

        return [NodeInfo(metadata) for metadata in payload.announce_nodes]

    async def public_information(self, secure_contact: SecureContact) -> NodeInfo:
        response_bytes = await self._http_communicate(secure_contact, NodeRoutes.PUBLIC_INFORMATION)
        metadata = try_deserialize(response_bytes, NodeMetadata)
        return NodeInfo(metadata)

    async def reencrypt(
        self,
        node_info: VerifiedNodeInfo,
        capsules: list[Capsule],
        treasure_map: TreasureMap,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        conditions: Conditions | None = None,
        context: Context | None = None,
    ) -> list[VerifiedCapsuleFrag]:
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
        response_bytes = await self._http_communicate(
            node_info.secure_contact, NodeRoutes.REENCRYPT, bytes(request)
        )

        response = try_deserialize(response_bytes, ReencryptionResponse)

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
            raise PeerError.invalid_message(ReencryptionResponse, exc) from exc

        return verified_cfrags

    async def decrypt(
        self,
        node_info: VerifiedNodeInfo,
        request: EncryptedThresholdDecryptionRequest,
    ) -> EncryptedThresholdDecryptionResponse:
        response_bytes = await self._http_communicate(
            node_info.secure_contact, NodeRoutes.DECRYPT, bytes(request)
        )
        return try_deserialize(response_bytes, EncryptedThresholdDecryptionResponse)

    async def status(self, secure_contact: SecureContact) -> str:
        response_bytes = await self._http_communicate(secure_contact, NodeRoutes.STATUS)
        try:
            return response_bytes.decode()
        except UnicodeDecodeError as exc:
            # TODO: the error contents is the HTML page with Mako traceback,
            # process it accordingly.
            raise PeerError.invalid_message(str, exc) from exc
