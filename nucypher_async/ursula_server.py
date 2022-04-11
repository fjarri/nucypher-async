import datetime
import sys

import trio
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.identity import IdentityAddress, IdentityClient
from .drivers.payment import PaymentClient
from .drivers.ssl import SSLPrivateKey, SSLCertificate
from .drivers.rest_client import RESTClient, Contact, SSLContact, HTTPError
from .drivers.rest_app import make_ursula_app
from .drivers.rest_server import Server
from .drivers.time import Clock
from .learner import Learner, verify_metadata_shared
from .status import render_status
from .storage import InMemoryStorage
from .ursula import Ursula
from .config import UrsulaServerConfig
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER


def generate_metadata(clock, ssl_private_key, ursula, domain, staking_provider_address, contact):
    ssl_certificate = SSLCertificate.self_signed(clock, ssl_private_key, contact.host)
    payload = NodeMetadataPayload(staking_provider_address=bytes(staking_provider_address),
                                  domain=domain.value,
                                  timestamp_epoch=int(clock.utcnow().timestamp()),
                                  operator_signature=ursula.operator_signature,
                                  verifying_key=ursula.signer.verifying_key(),
                                  encrypting_key=ursula.encrypting_key,
                                  certificate_der=ssl_certificate.to_der_bytes(),
                                  host=contact.host,
                                  port=contact.port,
                                  )
    return NodeMetadata(signer=ursula.signer, payload=payload)


def verify_metadata(clock, metadata, ssl_private_key, ursula, domain, staking_provider_address, contact):

    derived_operator_address = verify_metadata_shared(clock, metadata, contact, domain)

    payload = metadata.payload

    certificate = SSLCertificate.from_der_bytes(payload.certificate_der)
    if certificate.public_key() != ssl_private_key.public_key():
        raise NodeVerificationError(
            f"Certificate public key mismatch: expected {ssl_private_key.public_key()},"
            f"{certificate.public_key()} in the certificate")

    payload_staking_provider_address = IdentityAddress(payload.staking_provider_address)
    if payload_staking_provider_address != staking_provider_address:
        raise ValueError(
            f"Staking provider address mismatch: {payload_staking_provider_address} in the metadata, "
            f"{staking_provider_address} recorded in the blockchain")

    if derived_operator_address != ursula.operator_address:
        raise ValueError(
            f"Operator address mismatch: {derived_operator_address} derived from the metadata, "
            f"{ursula.operator_address} supplied on start")

    if payload.verifying_key != ursula.signer.verifying_key():
        raise ValueError(
            f"Verifying key mismatch: {payload.verifying_key} in the metadata, "
            f"{ursula.signer.verifying_key()} derived from the master key")

    if payload.encrypting_key != ursula.encrypting_key:
        raise ValueError(
            f"Encrypting key mismatch: {payload.encrypting_key} in the metadata, "
            f"{ursula.encrypting_key} derived from the master key")


class UrsulaServer(Server):

    @classmethod
    async def async_init(
            cls,
            ursula: Ursula,
            config: UrsulaServerConfig,
            **kwds):

        logger = config.parent_logger.get_child('UrsulaServerInit')

        async with config.identity_client.session() as session:
            staking_provider_address = await session.get_staking_provider_address(ursula.operator_address)
            logger.info("Operator bonded to {}", staking_provider_address.as_checksum())

            balance = await session.get_balance(ursula.operator_address)
            logger.info("Operator balance: {}", balance)

            if not await session.is_staking_provider_authorized(staking_provider_address):
                logger.info("Staking provider {} is not authorized", staking_provider_address)
                raise RuntimeError("Staking provider is not authorized")

            # TODO: we can call confirm_operator_address() here if the operator is not confirmed
            confirmed = await session.is_operator_confirmed(ursula.operator_address)
            if not confirmed:
                logger.info("Operator {} is not confirmed", ursula.operator_address)
                raise RuntimeError("Operator is not confirmed")

        return cls(
            ursula=ursula,
            config=config,
            staking_provider_address=staking_provider_address,
            **kwds)

    def __init__(
            self,
            ursula: Ursula,
            config: UrsulaServerConfig,
            staking_provider_address: IdentityAddress):

        self.ursula = ursula
        self.staking_provider_address = staking_provider_address

        self._clock = config.clock
        self._logger = config.parent_logger.get_child('UrsulaServer')
        self._storage = config.storage
        self._ssl_private_key = ursula.make_ssl_private_key()

        metadata = self._storage.get_my_metadata()
        if metadata is not None:
            self._logger.debug("Found existing metadata, verifying")
            try:
                verify_metadata(
                    clock=self._clock,
                    metadata=metadata,
                    ssl_private_key=self._ssl_private_key,
                    ursula=self.ursula,
                    staking_provider_address=self.staking_provider_address,
                    contact=config.contact,
                    domain=config.domain)
            except Exception as e:
                self._logger.warn("Obsolete/invalid metadata found ({}), updating", str(e))
                metadata = None

        if metadata is None:
            self._logger.debug("Generating new metadata")
            metadata = generate_metadata(
                clock=self._clock,
                ssl_private_key=self._ssl_private_key,
                ursula=self.ursula,
                staking_provider_address=self.staking_provider_address,
                contact=config.contact,
                domain=config.domain)
            self._storage.set_my_metadata(metadata)

        self._ssl_certificate = SSLCertificate.from_der_bytes(metadata.payload.certificate_der)
        self._metadata = metadata

        self._ssl_contact = SSLContact(config.contact, self._ssl_certificate)

        self.learner = Learner(
            rest_client=config.rest_client,
            identity_client=config.identity_client,
            storage=config.storage,
            my_metadata=self._metadata,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=self._clock)

        self._payment_client = config.payment_client

        self._started_at = self._clock.utcnow()

        self.domain = config.domain

        self.started = False

    def ssl_contact(self):
        return self._ssl_contact

    def ssl_private_key(self):
        return self._ssl_private_key

    def into_app(self):
        return make_ursula_app(self)

    def metadata(self):
        return self._metadata

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

    async def endpoint_ping(self, remote_address):
        return remote_address

    async def endpoint_node_metadata_get(self):
        response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                                                   announce_nodes=self.learner.metadata_to_announce())
        response = MetadataResponse(self.ursula.signer, response_payload)
        return bytes(response)

    async def endpoint_node_metadata_post(self, remote_address, metadata_request_bytes):
        metadata_request = MetadataRequest.from_bytes(metadata_request_bytes)

        if metadata_request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp_epoch,
                                                       announce_nodes=[])
            return bytes(MetadataResponse(self.ursula.signer, response_payload))

        new_metadatas = metadata_request.announce_nodes

        next_verification_in = self.learner.passive_learning(remote_address, new_metadatas)
        if next_verification_in is not None:
            self._logger.debug("After the pasive learning, new verification round in {}", next_verification_in)
            # TODO: don't reset if there's less than a certain timeout before awakening
            self._verification_task.reset(next_verification_in)

        return await self.endpoint_node_metadata_get()

    async def endpoint_public_information(self):
        return bytes(self._metadata)

    async def endpoint_reencrypt(self, reencryption_request_bytes):
        reencryption_request = ReencryptionRequest.from_bytes(reencryption_request_bytes)

        hrac = reencryption_request.hrac

        # TODO: check if the policy is marked as revoked
        async with self._payment_client.session() as session:
            if not await session.is_policy_active(hrac):
                raise HTTPError(f"Policy {hrac} is not active", status=HTTPStatus.PAYMENT_REQUIRED)

        verified_kfrag = self.ursula.decrypt_kfrag(
            encrypted_kfrag=reencryption_request.encrypted_kfrag,
            hrac=hrac,
            publisher_verifying_key=reencryption_request.publisher_verifying_key)

        vcfrags = self.ursula.reencrypt(verified_kfrag=verified_kfrag, capsules=reencryption_request.capsules)

        response = ReencryptionResponse(
            signer=self.ursula.signer,
            capsules=reencryption_request.capsules,
            vcfrags=vcfrags)

        return bytes(response)

    async def endpoint_status(self):
        return render_status(self._logger, self._clock, self, is_active_peer=True)
