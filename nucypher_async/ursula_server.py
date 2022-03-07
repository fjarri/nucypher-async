import trio
import maya
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.eth_client import BaseEthClient, Address
from .drivers.ssl import SSLPrivateKey, SSLCertificate
from .drivers.rest_client import RESTClient, Contact, SSLContact, HTTPError
from .learner import Learner
from .ursula import Ursula
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER


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
            parent_logger=NULL_LOGGER):

        self._logger = parent_logger.get_child('UrsulaServer')

        self._ssl_private_key = ursula.make_ssl_private_key()
        self._ssl_certificate = SSLCertificate.self_signed(self._ssl_private_key, host)

        contact = Contact(host=host, port=port)
        self.ssl_contact = SSLContact(contact, self._ssl_certificate)

        if _rest_client is None:
            _rest_client = RESTClient()

        self.ursula = ursula
        self.staker_address = staker_address

        payload = NodeMetadataPayload(staker_address=bytes(self.staker_address),
                                      domain=self.ursula.domain,
                                      timestamp_epoch=maya.now().epoch,
                                      decentralized_identity_evidence=self.ursula.decentralized_identity_evidence,
                                      verifying_key=self.ursula.signer.verifying_key(),
                                      encrypting_key=self.ursula.encrypting_key,
                                      certificate_bytes=self._ssl_certificate.to_pem_bytes(),
                                      host=host,
                                      port=port,
                                      )
        self._metadata = NodeMetadata(signer=self.ursula.signer,
                                      payload=payload)

        self.learner = Learner(
            _rest_client, eth_client,
            my_metadata=self._metadata,
            seed_contacts=seed_contacts,
            parent_logger=self._logger)

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
            # TODO: log the error here
            raise
            pass
        await this_task.restart_in(10)

    def stop(self):
        assert self.started

        self._learning_task.stop()

        self.started = False

    async def endpoint_ping(self, remote_address):
        return remote_address

    async def endpoint_node_metadata_get(self):
        response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state_timestamp.epoch,
                                                   announce_nodes=self.learner.metadata_to_announce())
        response = MetadataResponse(self.ursula.signer, response_payload)
        return bytes(response)

    async def endpoint_node_metadata_post(self, metadata_request_bytes):
        metadata_request = MetadataRequest.from_bytes(metadata_request_bytes)

        if metadata_request.fleet_state_checksum == self.learner.fleet_state_checksum:
            # No nodes in the response: same fleet state
            response_payload = MetadataResponsePayload(timestamp_epoch=self.learner.fleet_state_timestamp.epoch,
                                                       announce_nodes=[])
            return bytes(MetadataResponse(self.ursula.signer, response_payload))

        self.learner.add_metadata(metadata_request.announce_nodes)

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
