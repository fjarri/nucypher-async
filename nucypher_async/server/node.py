import trio
from nucypher_core import (
    MetadataRequest,
    MetadataResponse,
    MetadataResponsePayload,
    NodeMetadata,
    ReencryptionRequest,
    ReencryptionResponse,
)

from ..base.peer_error import GenericPeerError, InactivePolicy
from ..characters.pre import PublisherCard, Reencryptor
from ..drivers.identity import IdentityAddress
from ..drivers.peer import BasePeerAndNodeServer, PeerPrivateKey, SecureContact
from ..p2p.algorithms import learning_task, verification_task
from ..p2p.learner import Learner
from ..p2p.node_info import NodeInfo
from ..p2p.verification import PeerVerificationError, VerifiedNodeInfo, verify_staking_local
from ..utils import BackgroundTask
from ..utils.logging import Logger
from .config import NodeServerConfig, PeerServerConfig
from .status import render_status


class NodeServer(BasePeerAndNodeServer):
    @classmethod
    async def async_init(
        cls,
        reencryptor: Reencryptor,
        peer_server_config: PeerServerConfig,
        config: NodeServerConfig,
    ) -> "NodeServer":
        async with config.identity_client.session() as session:
            staking_provider_address = await verify_staking_local(
                session, reencryptor.operator_address
            )

        return cls(
            reencryptor=reencryptor,
            peer_server_config=peer_server_config,
            config=config,
            staking_provider_address=staking_provider_address,
        )

    def __init__(
        self,
        reencryptor: Reencryptor,
        peer_server_config: PeerServerConfig,
        config: NodeServerConfig,
        staking_provider_address: IdentityAddress,
    ):
        self.reencryptor = reencryptor

        self._clock = config.clock
        self._logger = config.parent_logger.get_child("NodeServer")
        self._storage = config.storage

        node_info = self._storage.get_my_node_info()
        maybe_node: VerifiedNodeInfo | None = None

        peer_private_key = (
            peer_server_config.peer_private_key or reencryptor.make_peer_private_key()
        )

        if node_info is not None:
            self._logger.debug("Found existing metadata, verifying")

            try:
                maybe_node = VerifiedNodeInfo.checked_local(
                    clock=self._clock,
                    node_info=node_info,
                    reencryptor=self.reencryptor,
                    staking_provider_address=staking_provider_address,
                    contact=peer_server_config.contact,
                    domain=config.domain,
                    peer_public_key=peer_server_config.peer_public_key,
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
                peer_public_key=peer_server_config.peer_public_key,
                signer=self.reencryptor.signer,
                operator_signature=self.reencryptor.operator_signature,
                encrypting_key=self.reencryptor.encrypting_key,
                dkg_key=self.reencryptor.dkg_key,
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
        self._pre_client = config.pre_client

        self._started_at = self._clock.utcnow()

        async def _verification_task(stop_event: trio.Event) -> None:
            await verification_task(stop_event, self.learner)

        async def _learning_task(stop_event: trio.Event) -> None:
            await learning_task(stop_event, self.learner)

        self._verification_task = BackgroundTask(worker=_verification_task, logger=self._logger)
        self._learning_task = BackgroundTask(worker=_learning_task, logger=self._logger)

        self.started = False

    def secure_contact(self) -> SecureContact:
        return self._node.secure_contact

    def peer_private_key(self) -> PeerPrivateKey:
        return self._peer_private_key

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
            return remote_host.encode()
        raise GenericPeerError

    async def node_metadata_get(self) -> MetadataResponse:
        announce_nodes = [
            m.metadata for m in self.learner.get_verified_nodes(include_this_node=True)
        ]
        response_payload = MetadataResponsePayload(
            timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
            announce_nodes=announce_nodes,
        )
        return MetadataResponse(self.reencryptor.signer, response_payload)

    async def node_metadata_post(
        self, remote_host: str | None, request: MetadataRequest
    ) -> MetadataResponse:
        if request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(
                timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                announce_nodes=[],
            )
            return MetadataResponse(self.reencryptor.signer, response_payload)

        new_metadatas = [NodeInfo(m) for m in request.announce_nodes]

        self.learner.passive_learning(remote_host, new_metadatas)

        return await self.node_metadata_get()

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
            signer=self.reencryptor.signer,
            capsules_and_vcfrags=list(zip(request.capsules, vcfrags, strict=True)),
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
