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
    ThresholdDecryptionResponse,
)
from nucypher_core.ferveo import AggregatedTranscript, Validator

from ..base.node import BaseNodeServer
from ..base.peer_error import GenericPeerError, InactivePolicy
from ..base.server import ServerWrapper
from ..base.types import JSON
from ..characters.cbd import Decryptor
from ..characters.node import Operator
from ..characters.pre import PublisherCard, Reencryptor
from ..drivers.asgi_app import make_node_asgi_app
from ..drivers.identity import IdentityAddress
from ..drivers.peer import BasePeerServer, PeerPrivateKey, SecureContact
from ..p2p.algorithms import learning_task, verification_task
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

        peer_private_key = (
            peer_server_config.peer_private_key or reencryptor.make_peer_private_key()
        )

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
                signer=self.operator.signer,
                operator_signature=self.operator.signature,
                encrypting_key=self.reencryptor.encrypting_key,
                dkg_key=self.decryptor.ritual_public_key,
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
        self._bind_to = peer_server_config.bind_to

        self._pre_client = config.pre_client
        self._cbd_client = config.cbd_client

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

    def bind_to(self) -> IPv4Address:
        return self._bind_to

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
            return remote_host.encode()
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

        new_metadatas = [NodeInfo(m) for m in request.announce_nodes]

        self.learner.passive_learning(remote_host, new_metadatas)

        announce_nodes = [
            m.metadata for m in self.learner.get_verified_nodes(include_this_node=True)
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
            ritual = await session.get_ritual(decryption_request.ritual_id)  # TODO: can be cached

            validators = []
            for i, staking_provider_address in enumerate(ritual.providers):
                if staking_provider_address == self._node.staking_provider_address:
                    # Local
                    public_key = self.decryptor.ritual_public_key
                else:
                    # Remote
                    # TODO: optimize rpc calls by obtaining public keys altogether
                    #  instead of one-by-one?
                    public_key = await session.get_provider_public_key(
                        provider=staking_provider_address, ritual_id=ritual.id
                    )
                validator = Validator(
                    address=staking_provider_address.checksum,
                    public_key=public_key,
                    share_index=i,
                )
                validators.append(validator)

        # TODO: Workaround: add serialized public key to aggregated transcript.
        # Since we use serde/bincode in rust, we need a metadata field for the public key,
        # which is the field size,
        # as 8 bytes in little-endian. See ferveo#209
        public_key_metadata = b"0\x00\x00\x00\x00\x00\x00\x00"
        transcript = (
            bytes(ritual.aggregated_transcript) + public_key_metadata + bytes(ritual.public_key)
        )
        aggregated_transcript = AggregatedTranscript.from_bytes(transcript)
        me = next(
            (node for node in validators if node.address == self._node.staking_provider_address),
            None,
        )
        assert me is not None
        decryption_share = self.decryptor.produce_decryption_share(
            me=me,
            nodes=validators,
            threshold=ritual.threshold,
            shares=ritual.shares,
            ritual_id=ritual.id,
            aggregated_transcript=aggregated_transcript,
            ciphertext_header=ciphertext_header,
            aad=decryption_request.acp.aad(),
            variant=decryption_request.variant,
        )

        # return the decryption share
        decryption_response = ThresholdDecryptionResponse(
            ritual_id=ritual.id,
            decryption_share=bytes(decryption_share),
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
