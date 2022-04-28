import datetime
import sys

import trio
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.identity import IdentityAddress, IdentityClient
from .drivers.payment import PaymentClient
from .drivers.peer import Contact, SecureContact, InactivePolicy
from .drivers.rest_app import make_ursula_app
from .drivers.rest_server import Server
from .drivers.time import Clock
from .learner import Learner
from .status import render_status
from .storage import InMemoryStorage
from .ursula import Ursula
from .config import UrsulaServerConfig
from .utils import BackgroundTask
from .verification import PublicUrsula, verify_staking_local


class UrsulaServer(Server):

    @classmethod
    async def async_init(cls, ursula: Ursula, config: UrsulaServerConfig):

        async with config.identity_client.session() as session:
            staking_provider_address = await verify_staking_local(session, ursula.operator_address)

        return cls(
            ursula=ursula,
            config=config,
            staking_provider_address=staking_provider_address)

    def __init__(
            self,
            ursula: Ursula,
            config: UrsulaServerConfig,
            staking_provider_address: IdentityAddress):

        self.ursula = ursula

        self._clock = config.clock
        self._logger = config.parent_logger.get_child('UrsulaServer')
        self._storage = config.storage

        metadata = self._storage.get_my_metadata()
        if metadata is not None:
            self._logger.debug("Found existing metadata, verifying")
            try:
                node = PublicUrsula.checked_local(
                    metadata=metadata,
                    clock=self._clock,
                    ursula=self.ursula,
                    staking_provider_address=staking_provider_address,
                    contact=config.contact,
                    domain=config.domain)
            except Exception as e:
                self._logger.warn("Obsolete/invalid metadata found ({}), updating", str(e))
                metadata = None

        if metadata is None:
            self._logger.debug("Generating new metadata")
            node = PublicUrsula.generate(
                clock=self._clock,
                ursula=self.ursula,
                staking_provider_address=staking_provider_address,
                contact=config.contact,
                domain=config.domain)
            self._storage.set_my_metadata(node.metadata)

        self._node = node

        self.learner = Learner(
            peer_client=config.peer_client,
            identity_client=config.identity_client,
            storage=config.storage,
            this_node=node,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=self._clock)

        self._payment_client = config.payment_client

        self._started_at = self._clock.utcnow()

        self.started = False

    def secure_contact(self):
        return self._node.secure_contact

    def peer_private_key(self):
        return self.ursula.peer_private_key()

    def into_app(self):
        return make_ursula_app(self)

    async def start(self, nursery):
        assert not self.started

        await self.learner.seed_round()

        # TODO: can we move initialization to __init__()?
        self._verification_task = BackgroundTask(nursery, self._verification_worker)
        self._learning_task = BackgroundTask(nursery, self._learning_worker)

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._verification_task.start()
        self._learning_task.start()

        self.started = True

    async def _verification_worker(self, this_task):
        try:
            self._logger.debug("Starting a verification round")
            next_verification_in = await self.learner.verification_round()
            self._logger.debug("After the verification round, next verification in: {}", next_verification_in)
            min_time_between_rounds = datetime.timedelta(seconds=5) # TODO: remove hardcoding
            this_task.restart_in(max(next_verification_in, min_time_between_rounds))
        except Exception as e:
            self._logger.error("Uncaught exception in the verification task:", exc_info=sys.exc_info())

    async def _learning_worker(self, this_task):
        try:
            self._logger.debug("Starting a learning round")
            next_verification_in, next_learning_in = await self.learner.learning_round()
            self._logger.debug("After the learning round, next verification in: {}", next_verification_in)
            self._logger.debug("After the learning round, next learning in: {}", next_learning_in)
            this_task.restart_in(next_learning_in)
            self._verification_task.reset(next_verification_in)
        except Exception as e:
            self._logger.error("Uncaught exception in the learning task:", exc_info=sys.exc_info())

    def stop(self):
        assert self.started

        self._verification_task.stop()
        self._learning_task.stop()

        self.started = False

    async def endpoint_ping(self, request):
        return request.remote_host

    async def endpoint_node_metadata_get(self, _request):
        response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                                                   announce_nodes=self.learner.metadata_to_announce())
        response = MetadataResponse(self.ursula.signer, response_payload)
        return bytes(response)

    async def endpoint_node_metadata_post(self, request):
        try:
            metadata_request = MetadataRequest.from_bytes(request.data)
        except ValueError as exc:
            raise MessageFormatError.for_message(MetadataRequest, exc) from exc

        if metadata_request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                                                       announce_nodes=[])
            return bytes(MetadataResponse(self.ursula.signer, response_payload))

        new_metadatas = metadata_request.announce_nodes

        next_verification_in = self.learner.passive_learning(request.remote_host, new_metadatas)
        if next_verification_in is not None:
            self._logger.debug("After the pasive learning, new verification round in {}", next_verification_in)
            # TODO: don't reset if there's less than a certain timeout before awakening
            self._verification_task.reset(next_verification_in)

        return await self.endpoint_node_metadata_get(request)

    async def endpoint_public_information(self, _request):
        return bytes(self._node.metadata)

    async def endpoint_reencrypt(self, request):
        try:
            reencryption_request = ReencryptionRequest.from_bytes(request.data)
        except ValueError as exc:
            raise MessageFormatError.for_message(ReencryptionRequest, exc) from exc

        hrac = reencryption_request.hrac

        # TODO: check if the policy is marked as revoked
        async with self._payment_client.session() as session:
            if not await session.is_policy_active(hrac):
                raise InactivePolicy(f"Policy {hrac} is not active")

        # TODO: catch decryption errors and raise RPC error here
        verified_kfrag = self.ursula.decrypt_kfrag(
            encrypted_kfrag=reencryption_request.encrypted_kfrag,
            hrac=hrac,
            publisher_verifying_key=reencryption_request.publisher_verifying_key)

        # TODO: catch reencryption errors (if any) and raise RPC error here
        vcfrags = self.ursula.reencrypt(verified_kfrag=verified_kfrag, capsules=reencryption_request.capsules)

        response = ReencryptionResponse(
            signer=self.ursula.signer,
            capsules=reencryption_request.capsules,
            vcfrags=vcfrags)

        return bytes(response)

    async def endpoint_status(self):
        return render_status(self._logger, self._clock, self, is_active_peer=True)
