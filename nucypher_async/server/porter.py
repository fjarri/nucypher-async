import http
from typing import Tuple, List, Iterable

import attrs
import trio
from nucypher_core.umbral import PublicKey

from ..base.types import JSON
from ..base.http_server import BaseHTTPServer, ASGI3Framework
from ..base.porter import BasePorterServer
from ..drivers.identity import IdentityAddress
from ..drivers.asgi_app import make_porter_asgi_app, HTTPError
from ..utils import BackgroundTask
from ..utils.logging import Logger
from ..utils.ssl import SSLPrivateKey, SSLCertificate
from ..p2p.learner import Learner
from ..p2p.verification import VerifiedUrsulaInfo
from .config import PorterServerConfig
from .status import render_status
from .. import schema


@attrs.frozen
class GetUrsulasRequest:
    quantity: int
    include_ursulas: List[IdentityAddress] = []
    exclude_ursulas: List[IdentityAddress] = []


@attrs.frozen
class UrsulaResult:
    checksum_address: IdentityAddress
    uri: str
    encrypting_key: PublicKey


@attrs.frozen
class GetUrsulasResult:
    ursulas: List[UrsulaResult]


@attrs.frozen
class GetUrsulasResponse:
    result: GetUrsulasResult
    version: str


class PorterServer(BaseHTTPServer, BasePorterServer):
    def __init__(self, config: PorterServerConfig):
        self._clock = config.clock
        self._config = config
        self._logger = config.parent_logger.get_child("PorterServer")
        self.learner = Learner(
            peer_client=config.peer_client,
            identity_client=config.identity_client,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=config.clock,
            storage=config.storage,
        )

        self._verification_task = BackgroundTask(
            worker=self.learner.verification_task, logger=self._logger
        )
        self._learning_task = BackgroundTask(worker=self.learner.learning_task, logger=self._logger)
        self._staker_query_task = BackgroundTask(
            worker=self.learner.staker_query_task, logger=self._logger
        )

        self._started_at = self._clock.utcnow()

        self.started = False

    def host_and_port(self) -> Tuple[str, int]:
        return self._config.host, self._config.port

    def ssl_certificate(self) -> SSLCertificate:
        return self._config.ssl_certificate

    def ssl_private_key(self) -> SSLPrivateKey:
        return self._config.ssl_private_key

    def into_asgi_app(self) -> ASGI3Framework:
        return make_porter_asgi_app(self)

    def logger(self) -> Logger:
        return self._logger

    async def start(self, nursery: trio.Nursery) -> None:
        assert not self.started

        await self.learner.seed_round(must_succeed=True)

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._verification_task.start(nursery)
        self._learning_task.start(nursery)
        self._staker_query_task.start(nursery)

        self.started = True

    async def stop(self, nursery: trio.Nursery) -> None:
        assert self.started

        await self._verification_task.stop()
        await self._learning_task.stop()
        await self._staker_query_task.stop()

        self.started = False

    async def _get_ursulas(
        self,
        quantity: int,
        include_ursulas: Iterable[IdentityAddress],
        exclude_ursulas: Iterable[IdentityAddress],
    ) -> List[VerifiedUrsulaInfo]:
        nodes = []

        async with self.learner.verified_nodes_iter(
            include_ursulas, verified_within=60
        ) as node_iter:
            async for node in node_iter:
                nodes.append(node)

        if len(nodes) < quantity:
            overhead = max(1, (quantity - len(nodes)) // 5)
            async with self.learner.random_verified_nodes_iter(
                amount=quantity,
                overhead=overhead,
                verified_within=60,
            ) as node_iter:
                async for node in node_iter:
                    nodes.append(node)

        return nodes

    async def endpoint_get_ursulas(self, request_json: JSON) -> JSON:
        try:
            request = schema.from_json(GetUrsulasRequest, request_json)
        except Exception as exc:  # TODO: catch the validation error
            raise HTTPError(str(exc), http.HTTPStatus.BAD_REQUEST) from exc

        if request.quantity > len(self.learner.fleet_sensor._staking_providers):
            raise HTTPError("Not enough stakers", http.HTTPStatus.BAD_REQUEST)

        # TODO: add support for excluding Ursulas
        if request.exclude_ursulas:
            raise HTTPError(
                "Excluding Ursulas is currently not supported", http.HTTPStatus.BAD_REQUEST
            )

        try:
            with trio.fail_after(5):
                nodes = await self._get_ursulas(
                    quantity=request.quantity,
                    include_ursulas=request.include_ursulas,
                    exclude_ursulas=request.exclude_ursulas,
                )

        except trio.TooSlowError as exc:
            raise HTTPError(
                "Could not get all the nodes in time", http.HTTPStatus.GATEWAY_TIMEOUT
            ) from exc

        node_list = [
            UrsulaResult(
                checksum_address=node.staking_provider_address,
                uri=node.contact.uri(),
                encrypting_key=node.encrypting_key,
            )
            for node in nodes
        ]
        response = GetUrsulasResponse(
            result=GetUrsulasResult(ursulas=node_list), version="async-0.1.0-dev"
        )

        return schema.to_json(response)

    async def endpoint_retrieve_cfrags(self, request_json: JSON) -> JSON:
        raise NotImplementedError

    async def endpoint_status(self) -> str:
        return render_status(
            node=None,
            logger=self._logger,
            clock=self._clock,
            fleet_sensor=self.learner.fleet_sensor,
            started_at=self._started_at,
        )
