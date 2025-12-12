import http
from collections.abc import Mapping
from ipaddress import IPv4Address

import attrs
import trio

from .._drivers.asgi import HTTPError
from .._drivers.http_server import HTTPServable
from .._drivers.ssl import SSLCertificate, SSLPrivateKey
from .._utils import BackgroundTask
from ..characters.pre import DelegatorCard, RecipientCard, RetrievalKit
from ..client.network import NetworkClient
from ..client.pre import LocalPREClient
from ..logging import Logger
from ..node import render_status
from . import _schema
from ._config import ProxyServerConfig
from ._schema import (
    JSON,
    GetUrsulasRequest,
    GetUrsulasResponse,
    GetUrsulasResult,
    RetrieveCFragsRequest,
    ServerRetrievalResult,
    ServerRetrieveCFragsResponse,
    ServerRetrieveCFragsResult,
    UrsulaResult,
)


class ProxyServer(HTTPServable):
    def __init__(self, config: ProxyServerConfig):
        self._clock = config.clock
        self._config = config
        self._logger = config.logger
        self._network_client = NetworkClient(
            node_client=config.node_client,
            identity_client=config.identity_client,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=config.clock,
            storage=config.storage,
        )
        self._pre_client = config.pre_client
        self._cbd_client = config.cbd_client
        self._domain = config.domain

        # TODO: generate self-signed ones if these are missing in the config?
        if config.http_server_config.ssl_config is None:
            raise ValueError("SSL keypair must be specified for a proxy server")
        self._ssl_config = config.http_server_config.ssl_config

        self._verification_task = BackgroundTask(
            worker=self._network_client.verification_task, logger=self._logger
        )
        self._learning_task = BackgroundTask(
            worker=self._network_client.learning_task, logger=self._logger
        )
        self._staker_query_task = BackgroundTask(
            worker=self._network_client.staker_query_task, logger=self._logger
        )

        self._started_at = self._clock.utcnow()

        self.started = False

    def bind_pair(self) -> tuple[IPv4Address, int]:
        return (
            self._config.http_server_config.bind_to_address,
            self._config.http_server_config.bind_to_port,
        )

    def ssl_certificate(self) -> SSLCertificate:
        return self._ssl_config.certificate

    def ssl_private_key(self) -> SSLPrivateKey:
        return self._ssl_config.private_key

    def ssl_ca_chain(self) -> list[SSLCertificate]:
        return self._ssl_config.ca_chain

    def logger(self) -> Logger:
        return self._logger

    async def start(self, nursery: trio.Nursery) -> None:
        if self.started:
            raise RuntimeError("The loop is already started")

        # TODO: get rid of ._learner access
        await self._network_client._learner.seed_round(must_succeed=True)  # noqa: SLF001

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._verification_task.start(nursery)
        self._learning_task.start(nursery)
        self._staker_query_task.start(nursery)

        self.started = True

    async def stop(self) -> None:
        if not self.started:
            raise RuntimeError("The loop is not started")

        await self._verification_task.stop()
        await self._learning_task.stop()
        await self._staker_query_task.stop()

        self.started = False

    async def get_ursulas(
        self, request_params: Mapping[str, str], request_body: JSON | None
    ) -> JSON:
        try:
            request = GetUrsulasRequest.from_query_params(request_params)
        except _schema.ValidationError as exc:
            raise HTTPError(http.HTTPStatus.BAD_REQUEST, str(exc)) from exc

        if request_body is not None:
            try:
                request_from_body = _schema.from_json(GetUrsulasRequest, request_body)
            except _schema.ValidationError as exc:
                raise HTTPError(http.HTTPStatus.BAD_REQUEST, str(exc)) from exc

            # TODO: kind of weird. Who would use both query params and body?
            # Also, should GET request even support a body?
            # What does the reference implementation do?
            request = attrs.evolve(
                request_from_body,
                quantity=request.quantity,
                include_ursulas=request.include_ursulas,
                exclude_ursulas=request.exclude_ursulas,
            )

        try:
            with trio.fail_after(5):
                nodes = await self._network_client.get_nodes(
                    quantity=request.quantity,
                    include_nodes=request.include_ursulas,
                    exclude_nodes=request.exclude_ursulas,
                )
        except RuntimeError as exc:
            raise HTTPError(http.HTTPStatus.BAD_REQUEST, str(exc)) from exc
        except trio.TooSlowError as exc:
            raise HTTPError(
                http.HTTPStatus.GATEWAY_TIMEOUT,
                "Could not get all the nodes in time",
            ) from exc

        node_list = [
            UrsulaResult(
                checksum_address=node.staking_provider_address,
                uri=node.contact.uri(),
                encrypting_key=node.pre_encrypting_key,
            )
            for node in nodes
        ]
        response = GetUrsulasResponse(
            result=GetUrsulasResult(ursulas=node_list), version="async-0.1.0-dev"
        )

        return _schema.to_json(response)

    async def retrieve_cfrags(self, request_body: JSON) -> JSON:
        try:
            request = _schema.from_json(RetrieveCFragsRequest, request_body)
        except _schema.ValidationError as exc:
            raise HTTPError(http.HTTPStatus.BAD_REQUEST, str(exc)) from exc

        client = LocalPREClient(self._network_client, self._pre_client)

        assert len(request.retrieval_kits) == 1  # TODO: support retrieving multiple kits
        outcome = await client.retrieve(
            treasure_map=request.treasure_map,
            message_kit=RetrievalKit(request.retrieval_kits[0]),
            delegator_card=DelegatorCard(request.alice_verifying_key),
            recipient_card=RecipientCard(request.bob_encrypting_key, request.bob_verifying_key),
        )

        retrieval_results = [ServerRetrievalResult(outcome.cfrags)]

        response = ServerRetrieveCFragsResponse(
            result=ServerRetrieveCFragsResult(retrieval_results=retrieval_results),
            version="async-0.1.0-dev",
        )

        return _schema.to_json(response)

    async def status(self) -> str:
        return render_status(
            node=None,
            logger=self._logger,
            clock=self._clock,
            snapshot=self._network_client.get_snapshot(),
            started_at=self._started_at,
            domain=self._domain,
        )
