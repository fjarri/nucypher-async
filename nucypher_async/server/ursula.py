from collections.abc import Sequence
from http import HTTPStatus

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
from nucypher_core.ferveo import Transcript, Validator

from ..base.peer_error import GenericPeerError, InactivePolicy
from ..characters.pre import PublisherCard, Ursula
from ..drivers.asgi_app import HTTPError
from ..drivers.cbd import Ritual
from ..drivers.identity import IdentityAddress
from ..drivers.peer import BasePeerAndUrsulaServer, PeerPrivateKey, SecureContact
from ..p2p.algorithms import learning_task, verification_task, verified_nodes_iter
from ..p2p.learner import Learner
from ..p2p.ursula import UrsulaInfo
from ..p2p.verification import PeerVerificationError, VerifiedUrsulaInfo, verify_staking_local
from ..utils import BackgroundTask
from ..utils.logging import Logger
from .config import PeerServerConfig, UrsulaServerConfig
from .status import render_status


class UrsulaServer(BasePeerAndUrsulaServer):
    @classmethod
    async def async_init(
        cls, ursula: Ursula, peer_server_config: PeerServerConfig, config: UrsulaServerConfig
    ) -> "UrsulaServer":
        async with config.identity_client.session() as session:
            staking_provider_address = await verify_staking_local(session, ursula.operator_address)

        return cls(
            ursula=ursula,
            peer_server_config=peer_server_config,
            config=config,
            staking_provider_address=staking_provider_address,
        )

    def __init__(
        self,
        ursula: Ursula,
        peer_server_config: PeerServerConfig,
        config: UrsulaServerConfig,
        staking_provider_address: IdentityAddress,
    ):
        self.ursula = ursula

        self._clock = config.clock
        self._logger = config.parent_logger.get_child("UrsulaServer")
        self._storage = config.storage

        ursula_info = self._storage.get_my_ursula_info()
        maybe_node: VerifiedUrsulaInfo | None = None

        peer_private_key = peer_server_config.peer_private_key or ursula.make_peer_private_key()

        if ursula_info is not None:
            self._logger.debug("Found existing metadata, verifying")

            try:
                maybe_node = VerifiedUrsulaInfo.checked_local(
                    clock=self._clock,
                    ursula_info=ursula_info,
                    ursula=self.ursula,
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
            self._node = VerifiedUrsulaInfo.generate(
                clock=self._clock,
                peer_private_key=peer_private_key,
                peer_public_key=peer_server_config.peer_public_key,
                signer=self.ursula.signer,
                operator_signature=self.ursula.operator_signature,
                encrypting_key=self.ursula.encrypting_key,
                dkg_key=self.ursula.dkg_key,
                staking_provider_address=staking_provider_address,
                contact=peer_server_config.contact,
                domain=config.domain,
            )
            self._storage.set_my_ursula_info(self._node)
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
        self._cbd_client = config.cbd_client
        self._identity_client = config.identity_client

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
            m.metadata for m in self.learner.get_verified_ursulas(include_this_node=True)
        ]
        response_payload = MetadataResponsePayload(
            timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
            announce_nodes=announce_nodes,
        )
        return MetadataResponse(self.ursula.signer, response_payload)

    async def node_metadata_post(
        self, remote_host: str | None, request: MetadataRequest
    ) -> MetadataResponse:
        if request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(
                timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                announce_nodes=[],
            )
            return MetadataResponse(self.ursula.signer, response_payload)

        new_metadatas = [UrsulaInfo(m) for m in request.announce_nodes]

        self.learner.passive_learning(remote_host, new_metadatas)

        return await self.node_metadata_get()

    async def public_information(self) -> NodeMetadata:
        # TODO: can we just return UrsulaInfo?
        return self._node.metadata

    async def decrypt(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> EncryptedThresholdDecryptionResponse:
        decryption_request = self.ursula.decrypt_threshold_decryption_request(request)
        self._logger.info(
            f"Threshold decryption request for ritual ID #{decryption_request.ritual_id}"
        )

        #self._verify_active_ritual(decryption_request)
        async with self._cbd_client.session() as session:
            assert session.is_ritual_active(decryption_request.ritual_id)
            assert session.is_participant(decryption_request.ritual_id, self.staking_provider_address)

        #self._verify_encryption_authorization(decryption_request)
        ciphertext_header = decryption_request.ciphertext_header
        authorization = decryption_request.acp.authorization
        async with self._cbd_client.session() as session:
            assert session.is_encryption_authorized(
                ritual_id=decryption_request.ritual_id,
                evidence=authorization,
                ciphertext_header=bytes(ciphertext_header),
            )

        # TODO: evaluate and check conditions here

        async with self._cbd_client.session() as session:
            ritual = await session.get_ritual(decryption_request.ritual_id)  # TODO: can be cached

            validators = []
            for i, staking_provider_address in enumerate(ritual.providers):
                if self.checksum_address == self.ursula.staking_provider_address:
                    # Local
                    public_key = self.ursula.ritual_public_key
                else:
                    # Remote
                    # TODO optimize rpc calls by obtaining public keys altogether
                    #  instead of one-by-one?
                    public_key = await session.get_provider_public_key(
                        provider=staking_provider_address, ritual_id=ritual.id
                    )
                validator = Validator(
                    address=staking_provider_address,
                    public_key=public_key,
                    share_index=i,
                )
                validators.append(validator)

        # FIXME: Workaround: add serialized public key to aggregated transcript.
        # Since we use serde/bincode in rust, we need a metadata field for the public key, which is the field size,
        # as 8 bytes in little-endian. See ferveo#209
        public_key_metadata = b"0\x00\x00\x00\x00\x00\x00\x00"
        transcript = (
            bytes(ritual.aggregated_transcript)
            + public_key_metadata
            + bytes(ritual.public_key)
        )
        aggregated_transcript = AggregatedTranscript.from_bytes(transcript)
        decryption_share = self.ursula.produce_decryption_share(
            nodes=validators,
            threshold=ritual.threshold,
            shares=ritual.shares,
            checksum_address=self.checksum_address,
            ritual_id=ritual.id,
            aggregated_transcript=aggregated_transcript,
            ciphertext_header=ciphertext_header,
            aad=aad,
            variant=variant,
        )

        # return the decryption share
        decryption_response = ThresholdDecryptionResponse(
            ritual_id=ritual.id,
            decryption_share=bytes(decryption_share),
        )
        return self.ursula.encrypt_threshold_decryption_response(
            response=decryption_response,
            requester_public_key=request.requester_public_key,
        )

    async def _resolve_validators(
        self, ritual: Ritual, participants: Sequence[Ritual.Participant]
    ) -> list[Validator]:
        # enforces that the node is part of the ritual
        if self._node.staking_provider_address not in [p.provider for p in participants]:
            raise HTTPError(
                f"Node not part of ritual {ritual.id}",
                HTTPStatus.FORBIDDEN,
            )

        validators = [Validator(self._node.staking_provider_address.checksum, self.ursula.dkg_key)]

        addresses = [p.provider for p in participants]
        async with verified_nodes_iter(self.learner, addresses) as node_iter:
            async for node in node_iter:
                validators.append(
                    Validator(
                        address=node.staking_provider_address.checksum, public_key=node.dkg_key
                    )
                )

        return list(sorted(validators, key=lambda x: x.address))

    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse:
        hrac = request.hrac

        # TODO: check if the policy is marked as revoked
        async with self._pre_client.session() as session:
            if not await session.is_policy_active(hrac):
                raise InactivePolicy(f"Policy {hrac} is not active")

        # TODO: catch decryption errors and raise RPC error here
        verified_kfrag = self.ursula.decrypt_kfrag(
            encrypted_kfrag=request.encrypted_kfrag,
            hrac=hrac,
            publisher_card=PublisherCard(request.publisher_verifying_key),
        )

        # TODO: check conditions here

        # TODO: catch reencryption errors (if any) and raise RPC error here
        vcfrags = self.ursula.reencrypt(verified_kfrag=verified_kfrag, capsules=request.capsules)

        return ReencryptionResponse(
            signer=self.ursula.signer,
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
