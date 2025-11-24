import http
from ipaddress import IPv4Address

import attrs
import trio

from .. import schema
from ..base.porter import BasePorterServer
from ..base.server import ServerWrapper
from ..base.types import JSON
from ..characters.pre import DelegatorCard, RecipientCard, RetrievalKit
from ..client.network import NetworkClient
from ..client.pre import LocalPREClient
from ..drivers.asgi_app import HTTPError, make_porter_asgi_app
from ..drivers.peer import BasePeerServer, PeerPrivateKey, SecureContact
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
        self._network_client = NetworkClient(
            peer_client=config.peer_client,
            identity_client=config.identity_client,
            seed_contacts=config.seed_contacts,
            parent_logger=self._logger,
            domain=config.domain,
            clock=config.clock,
            storage=config.storage,
        )
        self._pre_client = config.pre_client

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

        try:
            with trio.fail_after(5):
                nodes = await self._network_client.get_nodes(
                    quantity=request.quantity,
                    include_nodes=request.include_ursulas,
                    exclude_nodes=request.exclude_ursulas,
                )
        except RuntimeError as exc:
            raise HTTPError(str(exc), http.HTTPStatus.BAD_REQUEST) from exc
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

        return schema.to_json(response)

    async def endpoint_status(self) -> str:
        return render_status(
            node=None,
            logger=self._logger,
            clock=self._clock,
            snapshot=self._network_client.get_snapshot(),
            started_at=self._started_at,
            domain=self._domain,
        )
