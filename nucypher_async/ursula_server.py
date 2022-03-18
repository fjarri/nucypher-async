import sys

import trio
import maya
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.identity import BaseIdentityClient, IdentityAddress
from .drivers.payment import BasePaymentClient
from .drivers.ssl import SSLPrivateKey, SSLCertificate
from .drivers.rest_client import RESTClient, Contact, SSLContact, HTTPError
from .learner import Learner, verify_metadata_shared
from .storage import InMemoryStorage
from .ursula import Ursula
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER


def generate_metadata(ssl_private_key, ursula, staking_provider_address, contact):
    ssl_certificate = SSLCertificate.self_signed(ssl_private_key, contact.host)
    payload = NodeMetadataPayload(staking_provider_address=bytes(staking_provider_address),
                                  domain=ursula.domain,
                                  timestamp_epoch=maya.now().epoch,
                                  operator_signature=ursula.operator_signature,
                                  verifying_key=ursula.signer.verifying_key(),
                                  encrypting_key=ursula.encrypting_key,
                                  # TODO: update to DER when Ibex has it
                                  certificate_der=ssl_certificate.to_pem_bytes(),
                                  host=contact.host,
                                  port=contact.port,
                                  )
    return NodeMetadata(signer=ursula.signer, payload=payload)


def verify_metadata(metadata, ssl_private_key, ursula, staking_provider_address, contact):

    derived_operator_address = verify_metadata_shared(metadata, contact, ursula.domain)

    payload = metadata.payload

    # TODO: update to DER when Ibex has it
    certificate = SSLCertificate.from_pem_bytes(payload.certificate_der)
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


class UrsulaServer:

    @classmethod
    async def async_init(
            cls,
            ursula: Ursula,
            identity_client: BaseIdentityClient,
            parent_logger=NULL_LOGGER,
            **kwds):

        staking_provider_address = await identity_client.get_staking_provider_address(ursula.operator_address)
        parent_logger.info("Operator bonded to {}", staking_provider_address.as_checksum())

        balance = await identity_client.get_balance(ursula.operator_address)
        parent_logger.info("Operator balance: {}", balance)
        # TODO: how much eth do we need to run a node?

        # TODO: we can call confirm_operator_address() here if the operator is not confirmed
        confirmed = await identity_client.is_operator_confirmed(ursula.operator_address)
        if not confirmed:
            parent_logger.info("Operator {} is not confirmed", ursula.operator_address)
            raise RuntimeError("Operator is not confirmed")

        return cls(
            ursula=ursula,
            identity_client=identity_client,
            staking_provider_address=staking_provider_address,
            parent_logger=parent_logger,
            **kwds)

    def __init__(
            self,
            ursula: Ursula,
            identity_client: BaseIdentityClient,
            payment_client: BasePaymentClient,
            staking_provider_address: IdentityAddress,
            _rest_client=None,
            port=9151,
            host='127.0.0.1',
            seed_contacts=[],
            parent_logger=NULL_LOGGER,
            storage=None):

        self._logger = parent_logger.get_child('UrsulaServer')

        self.ursula = ursula
        self.staking_provider_address = staking_provider_address

        if storage is None:
            storage = InMemoryStorage()
        self._storage = storage

        self._ssl_private_key = ursula.make_ssl_private_key()

        contact = Contact(host=host, port=port)

        metadata_in_storage = self._storage.get_my_metadata()
        if metadata_in_storage is None:
            self._logger.debug("Generating new metadata")
            metadata = generate_metadata(
                ssl_private_key=self._ssl_private_key,
                ursula=self.ursula,
                staking_provider_address=self.staking_provider_address,
                contact=contact)
            self._storage.set_my_metadata(metadata)
        else:
            metadata = metadata_in_storage
            self._logger.debug("Found existing metadata, verifying")
            try:
                verify_metadata(
                    metadata=metadata,
                    ssl_private_key=self._ssl_private_key,
                    ursula=self.ursula,
                    staking_provider_address=self.staking_provider_address,
                    contact=contact)
            except Exception as e:
                self._logger.warn(f"Obsolete/invalid metadata found ({e}), updating")
                metadata = generate_metadata(
                    ssl_private_key=self._ssl_private_key,
                    ursula=self.ursula,
                    staking_provider_address=self.staking_provider_address,
                    contact=contact)
                self._storage.set_my_metadata(metadata)

        # TODO: update to DER when Ibex has it
        self._ssl_certificate = SSLCertificate.from_pem_bytes(metadata.payload.certificate_der)
        self._metadata = metadata

        self.ssl_contact = SSLContact(contact, self._ssl_certificate)

        if _rest_client is None:
            _rest_client = RESTClient()

        self.learner = Learner(
            rest_client=_rest_client,
            identity_client=identity_client,
            storage=storage,
            my_metadata=self._metadata,
            seed_contacts=seed_contacts,
            parent_logger=self._logger,
            domain=ursula.domain)

        self._payment_client = payment_client

        self.started = False

    def metadata(self):
        return self._metadata

    def start(self, nursery):
        assert not self.started

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._learning_task = BackgroundTask(nursery, self._learn)

        self.started = True

    async def _learn(self, this_task):
        try:
            with trio.fail_after(5):
                await self.learner.learning_round()
        except trio.TooSlowError:
            # Better luck next time
            pass
        except Exception as e:
            self._logger.error("Uncaught exception during learning:", exc_info=sys.exc_info())

        await this_task.restart_in(60)

    def stop(self):
        assert self.started

        self._learning_task.stop()

        self.started = False

    async def endpoint_ping(self, remote_address):
        return remote_address

    async def endpoint_node_metadata_get(self):
        response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp.epoch,
                                                   announce_nodes=self.learner.metadata_to_announce())
        response = MetadataResponse(self.ursula.signer, response_payload)
        return bytes(response)

    async def endpoint_node_metadata_post(self, remote_address, metadata_request_bytes):
        metadata_request = MetadataRequest.from_bytes(metadata_request_bytes)

        if metadata_request.fleet_state_checksum == self.learner.fleet_state.checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state.timestamp.epoch,
                                                       announce_nodes=[])
            return bytes(MetadataResponse(self.ursula.signer, response_payload))

        new_metadatas = metadata_request.announce_nodes

        # Unfliltered metadata goes into FleetState for compatibility
        self.learner.fleet_state.add_metadatas(new_metadatas)

        # Filter out only the contact(s) with `remote_address`.
        # We're not going to trust all this metadata anyway.
        sender_metadatas = [
            metadata for metadata in new_metadatas
            if metadata.payload.host == remote_address]
        self.learner.fleet_sensor.add_contacts(sender_metadatas)

        return await self.endpoint_node_metadata_get()

    async def endpoint_public_information(self):
        return bytes(self._metadata)

    async def endpoint_reencrypt(self, reencryption_request_bytes):
        reencryption_request = ReencryptionRequest.from_bytes(reencryption_request_bytes)

        hrac = reencryption_request.hrac

        # TODO: check if the policy is marked as revoked
        if not await self._payment_client.is_policy_active(hrac):
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

        verified_nodes = self.learner.fleet_sensor._verified_nodes
        contacts = self.learner.fleet_sensor._contacts_to_addresses

        stats = (f"""
        Staking provider: {self.staking_provider_address}
        Operator: {self.ursula.operator_address}
        """ +
        "Verified nodes:\n" +
        "\n".join(str(node) for node in verified_nodes) +
        "\n" +
        "Contacts:\n" +
        "\n".join(f"{contact}: {list(addresses)}" for contact, addresses in contacts.items())
        )

        return stats.replace('\n', '<br/>')
