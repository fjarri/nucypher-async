from typing import Optional

import trio
from nucypher_core import (
    NodeMetadata,
    MetadataRequest,
    MetadataResponsePayload,
    MetadataResponse,
    ReencryptionRequest,
    ReencryptionResponse,
)

from ..base.peer_error import InactivePolicy, GenericPeerError
from ..drivers.identity import IdentityAddress
from ..drivers.peer import (
    BasePeerAndUrsulaServer,
    SecureContact,
    PeerPrivateKey,
)
from ..characters.pre import Ursula, PublisherCard
from ..utils import BackgroundTask
from ..utils.logging import Logger
from ..p2p.ursula import UrsulaInfo
from ..p2p.learner import Learner
from ..p2p.verification import VerifiedUrsulaInfo, verify_staking_local, PeerVerificationError
from .status import render_status
from .config import UrsulaServerConfig


class UrsulaServer(BasePeerAndUrsulaServer):
    @classmethod
    async def async_init(cls, ursula: Ursula, config: UrsulaServerConfig) -> "UrsulaServer":

        async with config.identity_client.session() as session:
            staking_provider_address = await verify_staking_local(session, ursula.operator_address)

        return cls(
            ursula=ursula,
            config=config,
            staking_provider_address=staking_provider_address,
        )

    def __init__(
        self,
        ursula: Ursula,
        config: UrsulaServerConfig,
        staking_provider_address: IdentityAddress,
    ):

        self.ursula = ursula

        self._clock = config.clock
        self._logger = config.parent_logger.get_child("UrsulaServer")
        self._storage = config.storage

        ursula_info = self._storage.get_my_ursula_info()
        maybe_node: Optional[VerifiedUrsulaInfo] = None
        if ursula_info is not None:
            self._logger.debug("Found existing metadata, verifying")
            try:
                maybe_node = VerifiedUrsulaInfo.checked_local(
                    clock=self._clock,
                    ursula_info=ursula_info,
                    ursula=self.ursula,
                    staking_provider_address=staking_provider_address,
                    contact=config.contact,
                    domain=config.domain,
                )
            except PeerVerificationError as exc:
                self._logger.warn(
                    f"Obsolete/invalid metadata found ({exc}), updating",
                    exc_info=True,
                )

        if maybe_node is None:
            self._logger.debug("Generating new metadata")
            self._node = VerifiedUrsulaInfo.generate(
                clock=self._clock,
                peer_private_key=self.ursula.peer_private_key(),
                signer=self.ursula.signer,
                operator_signature=self.ursula.operator_signature,
                encrypting_key=self.ursula.encrypting_key,
                staking_provider_address=staking_provider_address,
                contact=config.contact,
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

        self._payment_client = config.payment_client

        self._started_at = self._clock.utcnow()

        self._verification_task = BackgroundTask(
            worker=self.learner.verification_task, logger=self._logger
        )
        self._learning_task = BackgroundTask(worker=self.learner.learning_task, logger=self._logger)

        self.started = False

    def secure_contact(self) -> SecureContact:
        return self._node.secure_contact

    def peer_private_key(self) -> PeerPrivateKey:
        return self.ursula.peer_private_key()

    def logger(self) -> Logger:
        return self._logger

    async def start(self, nursery: trio.Nursery) -> None:
        assert not self.started

        self._logger.debug("Starting tasks")

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        await self.learner.seed_round(must_succeed=True)
        self._verification_task.start(nursery)
        self._learning_task.start(nursery)

        self._logger.debug("Finished starting tasks")

        self.started = True

    async def stop(self, nursery: trio.Nursery) -> None:
        assert self.started
        await self._learning_task.stop()
        await self._verification_task.stop()
        self.started = False

    async def endpoint_ping(self, remote_host: Optional[str]) -> bytes:
        if remote_host:
            return remote_host.encode()
        raise GenericPeerError()

    async def node_metadata_get(self) -> MetadataResponse:
        announce_nodes = [m.metadata for m in self.learner.metadata_to_announce()]
        response_payload = MetadataResponsePayload(
            timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
            announce_nodes=announce_nodes,
        )
        response = MetadataResponse(self.ursula.signer, response_payload)
        return response

    async def node_metadata_post(
        self, remote_host: Optional[str], request: MetadataRequest
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

    async def reencrypt(self, request: ReencryptionRequest) -> ReencryptionResponse:

        hrac = request.hrac

        # TODO: check if the policy is marked as revoked
        async with self._payment_client.session() as session:
            if not await session.is_policy_active(hrac):
                raise InactivePolicy(f"Policy {hrac} is not active")

        # TODO: catch decryption errors and raise RPC error here
        verified_kfrag = self.ursula.decrypt_kfrag(
            encrypted_kfrag=request.encrypted_kfrag,
            hrac=hrac,
            publisher_card=PublisherCard(request.publisher_verifying_key),
        )

        # TODO: catch reencryption errors (if any) and raise RPC error here
        vcfrags = self.ursula.reencrypt(verified_kfrag=verified_kfrag, capsules=request.capsules)

        response = ReencryptionResponse(
            signer=self.ursula.signer,
            capsules_and_vcfrags=list(zip(request.capsules, vcfrags)),
        )

        return response

    async def endpoint_status(self) -> str:
        return render_status(
            node=self._node,
            logger=self._logger,
            clock=self._clock,
            fleet_sensor=self.learner.fleet_sensor,
            started_at=self._started_at,
        )
