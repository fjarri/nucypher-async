import http
from typing import Tuple, Optional, Dict, List

import attrs
import trio

from ..base.types import JSON
from ..base.http_server import BaseHTTPServer, ASGIFramework
from ..base.porter import BasePorterServer
from ..characters.pre import DelegatorCard, RecipientCard
from ..client.pre import retrieve_via_learner, RetrievalState
from ..drivers.asgi_app import make_porter_asgi_app, HTTPError
from ..utils import BackgroundTask
from ..utils.logging import Logger
from ..utils.ssl import SSLPrivateKey, SSLCertificate
from ..p2p.learner import Learner
from ..p2p.algorithms import (
    get_ursulas,
    learning_task,
    verification_task,
    staker_query_task,
)
from .. import schema
from ..schema.porter import (
    GetUrsulasRequest,
    UrsulaResult,
    GetUrsulasResponse,
    GetUrsulasResult,
    ServerRetrieveCFragsResponse,
    ServerRetrieveCFragsResult,
    ServerRetrievalResult,
    RetrieveCFragsRequest,
)
from .config import PorterServerConfig
from .status import render_status


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

        async def _verification_task(stop_event: trio.Event) -> None:
            await verification_task(stop_event, self.learner)

        async def _learning_task(stop_event: trio.Event) -> None:
            await learning_task(stop_event, self.learner)

        async def _staker_query_task(stop_event: trio.Event) -> None:
            await staker_query_task(stop_event, self.learner)

        self._verification_task = BackgroundTask(worker=_verification_task, logger=self._logger)
        self._learning_task = BackgroundTask(worker=_learning_task, logger=self._logger)
        self._staker_query_task = BackgroundTask(worker=_staker_query_task, logger=self._logger)

        self._started_at = self._clock.utcnow()

        self.started = False

    def host_and_port(self) -> Tuple[str, int]:
        return self._config.host, self._config.port

    def ssl_certificate(self) -> SSLCertificate:
        return self._config.ssl_certificate

    def ssl_ca_chain(self) -> Optional[List[SSLCertificate]]:
        return self._config.ssl_ca_chain

    def ssl_private_key(self) -> SSLPrivateKey:
        return self._config.ssl_private_key

    def into_asgi_app(self) -> ASGIFramework:
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

    async def endpoint_get_ursulas(
        self, request_params: Dict[str, str], request_body: Optional[JSON]
    ) -> JSON:

        try:
            request = GetUrsulasRequest.from_query_params(request_params)
        except schema.ValidationError as exc:
            raise HTTPError(str(exc), http.HTTPStatus.BAD_REQUEST) from exc

        if request_body is not None:
            try:
                request_from_body = schema.from_json(GetUrsulasRequest, request_body)
            except schema.ValidationError as exc:
                raise HTTPError(str(exc), http.HTTPStatus.BAD_REQUEST) from exc

            # TODO: kind of weird. Who would use both query params and body?
            # Also, should GET request even support a body?
            # What does the reference implementation do?
            request = attrs.evolve(
                request_from_body,
                quantity=request.quantity,
                include_ursulas=request.include_ursulas,
                exclude_ursulas=request.exclude_ursulas,
            )

        if request.quantity > len(self.learner.get_available_staking_providers()):
            raise HTTPError("Not enough stakers", http.HTTPStatus.BAD_REQUEST)

        try:
            with trio.fail_after(5):
                nodes = await get_ursulas(
                    learner=self.learner,
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

    async def endpoint_retrieve_cfrags(self, request_body: JSON) -> JSON:
        try:
            request = schema.from_json(RetrieveCFragsRequest, request_body)
        except schema.ValidationError as exc:
            raise HTTPError(str(exc), http.HTTPStatus.BAD_REQUEST) from exc

        retrieval_states = [RetrievalState(rkit, {}) for rkit in request.retrieval_kits]

        new_states = await retrieve_via_learner(
            learner=self.learner,
            retrieval_states=retrieval_states,
            treasure_map=request.treasure_map,
            delegator_card=DelegatorCard(request.alice_verifying_key),
            recipient_card=RecipientCard(request.bob_encrypting_key, request.bob_verifying_key),
        )

        retrieval_results = [ServerRetrievalResult(state.vcfrags) for state in new_states]

        response = ServerRetrieveCFragsResponse(
            result=ServerRetrieveCFragsResult(retrieval_results=retrieval_results),
            version="async-0.1.0-dev",
        )

        return schema.to_json(response)

    async def endpoint_status(self) -> str:
        return render_status(
            node=None,
            logger=self._logger,
            clock=self._clock,
            snapshot=self.learner.get_snapshot(),
            started_at=self._started_at,
        )
