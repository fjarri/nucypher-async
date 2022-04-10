import datetime
import http
import sys

import trio
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .drivers.identity import IdentityAddress, IdentityClient
from .drivers.payment import PaymentClient
from .drivers.ssl import SSLPrivateKey, SSLCertificate
from .drivers.rest_app import make_porter_app
from .drivers.rest_server import Server
from .drivers.rest_client import RESTClient, Contact, SSLContact, HTTPError
from .drivers.time import Clock
from .master_key import MasterKey
from .learner import Learner, verify_metadata_shared
from .status import render_status
from .storage import InMemoryStorage
from .ursula import Ursula
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER


class PorterServer(Server):

    def __init__(
            self,
            identity_client: IdentityClient,
            payment_client: PaymentClient,
            port=9151,
            host='127.0.0.1',
            seed_contacts=[],
            parent_logger=NULL_LOGGER,
            domain='mainnet'):

        self._clock = SystemClock()

        master_key = MasterKey.random()
        contact = Contact(host=host, port=port)
        # TODO: use a proper CA cert
        self._ssl_private_key = master_key.make_ssl_private_key()
        certificate = SSLCertificate.self_signed(self._clock, self._ssl_private_key, contact.host)
        self._ssl_contact = SSLContact(contact, certificate)

        self._logger = parent_logger.get_child('UrsulaServer')

        self.learner = Learner(
            identity_client=identity_client,
            seed_contacts=seed_contacts,
            parent_logger=self._logger,
            domain=domain,
            clock=self._clock)

        self._payment_client = payment_client

        self.started = False

    def ssl_contact(self):
        return self._ssl_contact

    def ssl_private_key(self):
        return self._ssl_private_key

    def into_app(self):
        return make_porter_app(self)

    def start(self, nursery):
        assert not self.started

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

    async def _get_ursulas(self, quantity, include_ursulas, exclude_ursulas):
        nodes = []
        async with trio.open_nursery() as nursery:

            async with self.learner.verified_nodes_iter(include_ursulas, verified_within=60) as aiter:
                async for node in aiter:
                    nodes.append(node)

            if len(nodes) < quantity:
                async with self.learner.random_verified_nodes_iter(exclude_ursulas, verified_within=60) as aiter:
                    async for node in aiter:
                        nodes.append(node)
                        if len(nodes) == quantity:
                            break

        return nodes

    async def endpoint_get_ursulas(self, request_json):
        try:
            quantity = request_json['quantity']
            include_ursulas = request_json.get('include_ursulas', [])
            exclude_ursulas = request_json.get('exclude_ursulas', [])

            include_ursulas = [IdentityAddress.from_hex(address) for address in include_ursulas]
            exclude_ursulas = [IdentityAddress.from_hex(address) for address in exclude_ursulas]
        except Exception as e:
            raise HTTPError(str(e), http.HTTPStatus.BAD_REQUEST)

        try:
            with trio.fail_after(5):
                nodes = await self._get_ursulas(quantity, include_ursulas, exclude_ursulas)

        except trio.TooSlowError as e:
            raise HTTPError("Could not get all the nodes in time", http.HTTPStatus.GATEWAY_TIMEOUT) from e

        node_list = [dict(
            checksum_address=node.staking_provider_address.as_checksum(),
            uri=f"https://{node.ssl_contact.contact.host}:{node.ssl_contact.contact.port}",
            encrypting_key=bytes(node.encrypting_key).hex()
        ) for node in nodes]

        return dict(result=dict(ursulas=node_list), version="async-0.1.0-dev")

    async def endpoint_retrieve_cfrags(self, request_json):
        pass
