from ipaddress import IPv4Address

import trio
from nucypher_core import (
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    MetadataRequest,
    MetadataResponse,
    MetadataResponsePayload,
    NodeMetadata,
    ReencryptionRequest,
    ReencryptionResponse,
)

from ..base.node import BaseNodeServer
from ..base.peer_error import GenericPeerError, InactivePolicy
from ..base.server import ServerWrapper
from ..base.types import JSON
from ..characters.cbd import ActiveRitual, Decryptor
from ..characters.node import Operator
from ..characters.pre import PublisherCard, Reencryptor
from ..drivers.asgi_app import make_node_asgi_app
from ..drivers.identity import IdentityAddress
from ..drivers.peer import BasePeerServer, PeerPrivateKey, SecureContact
from ..p2p.learner import Learner
from ..p2p.node_info import NodeInfo
from ..p2p.verification import PeerVerificationError, VerifiedNodeInfo, verify_staking_local
from ..utils import BackgroundTask
from ..utils.logging import Logger
from .config import NodeServerConfig, PeerServerConfig
from .status import render_status


class NodeServer(BasePeerServer, BaseNodeServer):
    @classmethod
    async def async_init(
        cls,
        operator: Operator,
        reencryptor: Reencryptor,
        decryptor: Decryptor,
        peer_server_config: PeerServerConfig,
        config: NodeServerConfig,
    ) -> "NodeServer":
        async with config.identity_client.session() as session:
            staking_provider_address = await verify_staking_local(session, operator.address)

        return cls(
            operator=operator,
            reencryptor=reencryptor,
            decryptor=decryptor,
            peer_server_config=peer_server_config,
            config=config,
            staking_provider_address=staking_provider_address,
        )

    def __init__(
        self,
        operator: Operator,
        reencryptor: Reencryptor,
        decryptor: Decryptor,
        peer_server_config: PeerServerConfig,
        config: NodeServerConfig,
        staking_provider_address: IdentityAddress,
    ):
        self.operator = operator
        self.reencryptor = reencryptor
        self.decryptor = decryptor

        self._clock = config.clock
        self._logger = config.parent_logger.get_child("NodeServer")
        self._storage = config.storage

        node_info = self._storage.get_my_node_info()
        maybe_node: VerifiedNodeInfo | None = None

        peer_key_pair = peer_server_config.peer_key_pair
        if peer_key_pair is not None:
            peer_private_key, peer_public_key = peer_key_pair
        else:
            peer_private_key = reencryptor.make_peer_private_key()
            peer_public_key = None

        if node_info is not None:
            self._logger.debug("Found existing metadata, verifying")

            try:
                maybe_node = VerifiedNodeInfo.checked_local(
                    clock=self._clock,
                    node_info=node_info,
                    operator=operator,
                    reencryptor=self.reencryptor,
                    staking_provider_address=staking_provider_address,
                    contact=peer_server_config.contact,
                    domain=config.domain,
                    peer_public_key=peer_public_key,
                    peer_private_key=peer_private_key,
                )
            except PeerVerificationError as exc:
                self._logger.warning(
                    "Obsolete/invalid metadata found ({}), updating",
                    exc,
                    exc_info=True,
                )

        if maybe_node is None:
            self._logger.debug("Generating new metadata")
            self._node = VerifiedNodeInfo.generate(
                clock=self._clock,
                peer_private_key=peer_private_key,
                peer_public_key=peer_public_key,
                signer=self.operator.signer,
                operator_signature=self.operator.signature,
                encrypting_key=self.reencryptor.encrypting_key,
                dkg_key=self.decryptor.public_key,
                staking_provider_address=staking_provider_address,
                contact=peer_server_config.contact,
                domain=config.domain,
            )
            self._storage.set_my_node_info(self._node)
        else:
            self._node = maybe_node

        self.learner = Learner(
            this_node=self._node,
            peer_client=config.peer_client,
            identity_client=config.identity_client,
            storage=config.storage,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=self._clock,
        )

        self._peer_private_key = peer_private_key
        self._bind_pair = (peer_server_config.bind_to_address, peer_server_config.bind_to_port)

        self._pre_client = config.pre_client
        self._cbd_client = config.cbd_client

        self._started_at = self._clock.utcnow()

        self._verification_task = BackgroundTask(
            worker=self.learner.verification_task, logger=self._logger
        )
        self._learning_task = BackgroundTask(worker=self.learner.learning_task, logger=self._logger)

        self.started = False

    def secure_contact(self) -> SecureContact:
        return self._node.secure_contact

    def peer_private_key(self) -> PeerPrivateKey:
        return self._peer_private_key

    def bind_pair(self) -> tuple[IPv4Address, int]:
        return self._bind_pair

    def into_servable(self) -> ServerWrapper:
        return make_node_asgi_app(self)

    def logger(self) -> Logger:
        return self._logger

    async def start(self, nursery: trio.Nursery) -> None:
        if self.started:
            raise RuntimeError("The loop is already started")

        self._logger.debug("Starting tasks")

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        await self.learner.seed_round(must_succeed=True)
        self._verification_task.start(nursery)
        self._learning_task.start(nursery)

        self._logger.debug("Finished starting tasks")

        self.started = True

    async def stop(self) -> None:
        if not self.started:
            raise RuntimeError("The loop is not started")
        await self._learning_task.stop()
        await self._verification_task.stop()
        self.started = False

    async def endpoint_ping(self, remote_host: str | None) -> bytes:
        if remote_host:
            return str(remote_host).encode()
        raise GenericPeerError

    async def node_metadata(
        self, remote_host: str | None, request: MetadataRequest
    ) -> MetadataResponse:
        if request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(
                timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                announce_nodes=[],
            )
            return MetadataResponse(self.operator.signer, response_payload)

        # Filter out our own metadata
        node_infos = [NodeInfo(m) for m in request.announce_nodes]
        node_infos = [
            node_info
            for node_info in node_infos
            if node_info.staking_provider_address != self._node.staking_provider_address
        ]

        # TODO: this can work differently if the P2P network does not use HTTP.
        # But we still need some way to filter node infos based on who sent them, to avoid DDoS.
        # Also, the filtering out may need to be done here and not in Learner.
        self.learner.passive_learning(remote_host, node_infos)

        announce_nodes = [m.metadata for m in self.learner.get_verified_nodes()] + [
            self._node.metadata
        ]

        response_payload = MetadataResponsePayload(
            timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
            announce_nodes=announce_nodes,
        )
        return MetadataResponse(self.operator.signer, response_payload)

    async def public_information(self) -> NodeMetadata:
        # TODO: can we just return NodeInfo?
        return self._node.metadata

    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse:
        hrac = request.hrac

        # TODO: check if the policy is marked as revoked
        async with self._pre_client.session() as session:
            if not await session.is_policy_active(hrac):
                raise InactivePolicy(f"Policy {hrac} is not active")

        # TODO: catch decryption errors and raise RPC error here
        verified_kfrag = self.reencryptor.decrypt_kfrag(
            encrypted_kfrag=request.encrypted_kfrag,
            hrac=hrac,
            publisher_card=PublisherCard(request.publisher_verifying_key),
        )

        # TODO: check conditions here

        # TODO: catch reencryption errors (if any) and raise RPC error here
        vcfrags = self.reencryptor.reencrypt(
            verified_kfrag=verified_kfrag, capsules=request.capsules
        )

        return ReencryptionResponse(
            signer=self.operator.signer,
            capsules_and_vcfrags=list(zip(request.capsules, vcfrags, strict=True)),
        )

    async def endpoint_condition_chains(self) -> JSON:
        raise NotImplementedError

    async def decrypt(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> EncryptedThresholdDecryptionResponse:
        decryption_request = self.decryptor.decrypt_threshold_decryption_request(request)
        self._logger.info(
            "Threshold decryption request for ritual ID #{}", decryption_request.ritual_id
        )

        async with self._cbd_client.session() as session:
            assert await session.is_ritual_active(decryption_request.ritual_id)
            assert await session.is_participant(
                decryption_request.ritual_id, self._node.staking_provider_address
            )

        ciphertext_header = decryption_request.ciphertext_header
        authorization = decryption_request.acp.authorization
        async with self._cbd_client.session() as session:
            assert await session.is_authorized(
                ritual_id=decryption_request.ritual_id,
                evidence=authorization,
                ciphertext_header=ciphertext_header,
            )

        # TODO: evaluate and check conditions here

        async with self._cbd_client.session() as session:
            on_chain_ritual = await session.get_ritual(
                decryption_request.ritual_id
            )  # TODO: can be cached

            validators = {}
            for staking_provider_address in on_chain_ritual.providers:
                if staking_provider_address == self._node.staking_provider_address:
                    # Local
                    public_key = self.decryptor.public_key
                else:
                    # Remote
                    # TODO: optimize rpc calls by obtaining public keys altogether
                    #  instead of one-by-one?
                    public_key = await session.get_provider_public_key(
                        provider=staking_provider_address, ritual_id=on_chain_ritual.id
                    )
                validators[staking_provider_address] = public_key

        ritual = ActiveRitual.from_on_chain_ritual(on_chain_ritual, validators)
        decryption_share = self.decryptor.make_decryption_share(ritual, decryption_request)
        decryption_response = self.decryptor.make_threshold_decryption_response(
            ritual, decryption_share
        )
        return self.decryptor.encrypt_threshold_decryption_response(
            response=decryption_response,
            requester_public_key=request.requester_public_key,
        )

    async def endpoint_status(self) -> str:
        return render_status(
            node=self._node,
            logger=self._logger,
            clock=self._clock,
            snapshot=self.learner.get_snapshot(),
            started_at=self._started_at,
            domain=self._node.domain,
        )
