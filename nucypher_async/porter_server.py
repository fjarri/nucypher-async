import datetime
import http
import sys
from typing import Tuple

import trio
from nucypher_core import (
    NodeMetadataPayload, NodeMetadata, MetadataRequest, MetadataResponsePayload,
    MetadataResponse, ReencryptionRequest, ReencryptionResponse)

from .base.http_server import BaseHTTPServer
from .base.porter import BasePorter
from .drivers.identity import IdentityAddress, IdentityClient
from .drivers.payment import PaymentClient
from .drivers.asgi_app import make_porter_app, HTTPError
from .drivers.peer import Contact, SecureContact
from .master_key import MasterKey
from .learner import Learner
from .status import render_status
from .storage import InMemoryStorage
from .ursula import Ursula
from .utils import BackgroundTask
from .utils.logging import NULL_LOGGER
from .utils.ssl import SSLPrivateKey, SSLCertificate


class PorterServer(BaseHTTPServer, BasePorter):

    def __init__(self, config):
        self._clock = config.clock
        self._config = config
        self._logger = config.parent_logger.get_child('PorterServer')
        self.learner = Learner(
            identity_client=config.identity_client,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=config.clock,
            storage=config.storage)

        self._verification_task = BackgroundTask(worker=self.learner.verification_task, logger=self._logger)
        self._learning_task = BackgroundTask(worker=self.learner.learning_task, logger=self._logger)
        self._staker_query_task = BackgroundTask(worker=self._staker_query, logger=self._logger)

        self._started_at = self._clock.utcnow()

        self.started = False

    def host_and_port(self) -> Tuple[str, int]:
        return self._config.host, self._config.port

    def ssl_certificate(self) -> SSLCertificate:
        return self._config.ssl_certificate

    def ssl_private_key(self) -> SSLPrivateKey:
        return self._config.ssl_private_key

    def into_asgi_app(self):
        return make_porter_app(self)

    async def start(self, nursery):
        assert not self.started

        await self.learner.seed_round(must_succeed=True)

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._verification_task.start(nursery)
        self._learning_task.start(nursery)
        self._staker_query_task.start(nursery)

        self.started = True

    def stop(self):
        assert self.started

        self._verification_task.stop()
        self._learning_task.stop()
        self._staker_query_task.stop()

        self.started = False

    async def _get_ursulas(self, quantity, include_ursulas, exclude_ursulas):
        nodes = []
        async with trio.open_nursery() as nursery:

            async with self.learner.verified_nodes_iter(include_ursulas, verified_within=60) as aiter:
                async for node in aiter:
                    nodes.append(node)

            if len(nodes) < quantity:
                overhead = max(1, (quantity - len(nodes)) // 5)
                async with self.learner.random_verified_nodes_iter(
                        exclude=exclude_ursulas, amount=quantity,
                        overhead=overhead, verified_within=60) as aiter:
                    async for node in aiter:
                        nodes.append(node)

        return nodes

    async def endpoint_get_ursulas(self, request_json):
        try:
            quantity = request_json['quantity']
            if isinstance(quantity, str):
                quantity = int(quantity)
            include_ursulas = request_json.get('include_ursulas', [])
            exclude_ursulas = request_json.get('exclude_ursulas', [])

            include_ursulas = [IdentityAddress.from_hex(address) for address in include_ursulas]
            exclude_ursulas = [IdentityAddress.from_hex(address) for address in exclude_ursulas]
        except Exception as e:
            raise HTTPError(str(e), http.HTTPStatus.BAD_REQUEST)

        if quantity > len(self.learner.fleet_sensor._staking_providers):
            raise HTTPError("Not enough stakers", http.HTTPStatus.BAD_REQUEST)

        try:
            with trio.fail_after(5):
                nodes = await self._get_ursulas(quantity, include_ursulas, exclude_ursulas)

        except trio.TooSlowError as e:
            raise HTTPError("Could not get all the nodes in time", http.HTTPStatus.GATEWAY_TIMEOUT) from e

        node_list = [dict(
            checksum_address=node.staking_provider_address.checksum,
            uri=node.secure_contact.uri,
            encrypting_key=bytes(node.encrypting_key).hex()
        ) for node in nodes]

        return dict(result=dict(ursulas=node_list), version="async-0.1.0-dev")

    async def endpoint_retrieve_cfrags(self, request_json):
        pass

    async def endpoint_status(self):
        return render_status(self._logger, self._clock, self, is_active_peer=False)
