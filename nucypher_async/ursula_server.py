import sys

import trio
import maya
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.eth_client import BaseEthClient, Address
from .drivers.ssl import SSLPrivateKey, SSLCertificate
from .drivers.rest_client import RESTClient, Contact, SSLContact, HTTPError
from .learner import Learner, verify_metadata_shared
from .storage import InMemoryStorage
from .ursula import Ursula
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER


def generate_metadata(ssl_private_key, ursula, staker_address, contact):
    ssl_certificate = SSLCertificate.self_signed(ssl_private_key, contact.host)
    payload = NodeMetadataPayload(staker_address=bytes(staker_address),
                                  domain=ursula.domain,
                                  timestamp_epoch=maya.now().epoch,
                                  decentralized_identity_evidence=ursula.decentralized_identity_evidence,
                                  verifying_key=ursula.signer.verifying_key(),
                                  encrypting_key=ursula.encrypting_key,
                                  certificate_bytes=ssl_certificate.to_pem_bytes(),
                                  host=contact.host,
                                  port=contact.port,
                                  )
    return NodeMetadata(signer=ursula.signer, payload=payload)


def verify_metadata(metadata, ssl_private_key, ursula, staker_address, contact):

    derived_operator_address = verify_metadata_shared(metadata, contact, ursula.domain)

    payload = metadata.payload

    certificate = SSLCertificate.from_pem_bytes(payload.certificate_bytes)
    if certificate.public_key() != ssl_private_key.public_key():
        raise NodeVerificationError(
            f"Certificate public key mismatch: expected {ssl_private_key.public_key()},"
            f"{certificate.public_key()} in the certificate")

    payload_staker_address = Address(payload.staker_address)
    if payload_staker_address != staker_address:
        raise ValueError(
            f"Staker address mismatch: {payload_staker_address} in the metadata, "
            f"{staker_address} recorded in the blockchain")

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
            eth_client: BaseEthClient,
            parent_logger=NULL_LOGGER,
            **kwds):

        staker_address = await eth_client.get_staker_address(ursula.operator_address)
        parent_logger.info("Operator bonded to {}", staker_address.as_checksum())

        eth_balance = await eth_client.get_eth_balance(ursula.operator_address)
        parent_logger.info("Operator balance: {}", eth_balance)
        # TODO: how much eth do we need to run a node?

        # TODO: we can call confirm_operator_address() here if the operator is not confirmed
        confirmed = await eth_client.is_operator_confirmed(ursula.operator_address)
        if not confirmed:
            parent_logger.info("Operator {} is not confirmed", ursula.operator_address)
            raise RuntimeError("Operator is not confirmed")

        return cls(ursula, eth_client, staker_address=staker_address, parent_logger=parent_logger, **kwds)

    def __init__(
            self,
            ursula: Ursula,
            eth_client: BaseEthClient,
            staker_address: Address,
            _rest_client=None,
            port=9151,
            host='127.0.0.1',
            seed_contacts=[],
            parent_logger=NULL_LOGGER,
            storage=None):

        self._logger = parent_logger.get_child('UrsulaServer')

        self.ursula = ursula
        self.staker_address = staker_address

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
                staker_address=self.staker_address,
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
                    staker_address=self.staker_address,
                    contact=contact)
            except Exception as e:
                self._logger.warn(f"Obsolete/invalid metadata found ({e}), updating")
                metadata = generate_metadata(
                    ssl_private_key=self._ssl_private_key,
                    ursula=self.ursula,
                    staker_address=self.staker_address,
                    contact=contact)
                self._storage.set_my_metadata(metadata)

        self._ssl_certificate = SSLCertificate.from_pem_bytes(metadata.payload.certificate_bytes)
        self._metadata = metadata

        self.ssl_contact = SSLContact(contact, self._ssl_certificate)

        if _rest_client is None:
            _rest_client = RESTClient()

        self.learner = Learner(
            rest_client=_rest_client,
            eth_client=eth_client,
            storage=storage,
            my_metadata=self._metadata,
            seed_contacts=seed_contacts,
            parent_logger=self._logger,
            domain=ursula.domain)

        self._eth_client = eth_client

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
        self.learner.fleet_state.update(new_metadatas)

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

        # TODO: check if the policy is marked as revoked

        verified_kfrag = self.ursula.decrypt_kfrag(
            encrypted_kfrag=reencryption_request.encrypted_kfrag,
            hrac=reencryption_request.hrac,
            publisher_verifying_key=reencryption_request.publisher_verifying_key)

        """
        TODO: blockchain checks
        - verify that the policy has been paid for (by HRAC) (`verify_policy_payment`)
        - verify that the policy is active (`verify_active_policy`)
        """

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
        Staker: {self.staker_address}
        Operator: {self.ursula.operator_address}
        """ +
        "Verified nodes:\n" +
        "\n".join(str(node) for node in verified_nodes) +
        "\n" +
        "Contacts:\n" +
        "\n".join(f"{contact}: {list(addresses)}" for contact, addresses in contacts.items())
        )

        return stats.replace('\n', '<br/>')
