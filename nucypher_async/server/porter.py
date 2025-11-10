import http
from ipaddress import IPv4Address

import attrs
import trio

from .. import schema
from ..base.porter import BasePorterServer
from ..base.server import ServerWrapper
from ..base.types import JSON
from ..characters.pre import DelegatorCard, RecipientCard
from ..client.pre import RetrievalState, retrieve_via_learner
from ..drivers.asgi_app import HTTPError, make_porter_asgi_app
from ..drivers.peer import BasePeerServer, PeerPrivateKey, SecureContact
from ..p2p.algorithms import get_nodes, learning_task, staker_query_task, verification_task
from ..p2p.learner import Learner
from ..schema.porter import (
    GetUrsulasRequest,
    GetUrsulasResponse,
    GetUrsulasResult,
    RetrieveCFragsRequest,
    ServerRetrievalResult,
    ServerRetrieveCFragsResponse,
    ServerRetrieveCFragsResult,
    UrsulaResult,
)
from ..utils import BackgroundTask
from ..utils.logging import Logger
from .config import PeerServerConfig, PorterServerConfig
from .status import render_status


class PorterServer(BasePeerServer, BasePorterServer):
    def __init__(self, peer_server_config: PeerServerConfig, config: PorterServerConfig):
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

        self._contact = peer_server_config.contact

        # TODO: generate self-signed ones if these are missing in the config
        peer_key_pair = peer_server_config.peer_key_pair
        if peer_key_pair is not None:
            self._peer_private_key, self._peer_public_key = peer_key_pair
        else:
            raise NotImplementedError

        self._secure_contact = SecureContact(peer_server_config.contact, self._peer_public_key)
        self._bind_pair = (peer_server_config.bind_to_address, peer_server_config.bind_to_port)

        self._domain = config.domain

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

    def secure_contact(self) -> SecureContact:
        return self._secure_contact

    def peer_private_key(self) -> PeerPrivateKey:
        return self._peer_private_key

    def bind_pair(self) -> tuple[IPv4Address, int]:
        return self._bind_pair

    def into_servable(self) -> ServerWrapper:
        return make_porter_asgi_app(self)

    def logger(self) -> Logger:
        return self._logger

    async def start(self, nursery: trio.Nursery) -> None:
        if self.started:
            raise RuntimeError("The loop is already started")

        await self.learner.seed_round(must_succeed=True)

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

    async def endpoint_get_ursulas(
        self, request_params: dict[str, str], request_body: JSON | None
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
                nodes = await get_nodes(
                    learner=self.learner,
                    quantity=request.quantity,
                    include_nodes=request.include_ursulas,
                    exclude_nodes=request.exclude_ursulas,
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
            domain=self._domain,
        )
