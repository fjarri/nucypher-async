"""
Encapsulates the specific ASGI framework
used to create an ASGI app out of server objects.

This is a thin layer that serves the following purposes:
- Extract request body and/or arguments and pass those to the server object's endpoint;
- wrap the returned raw data into a response;
- catch exceptions and wrap them in corresponding HTTP responses.

Nothing else should be happening here, the bulk of the server logic is located in server objects.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping

import trio

from ..base.types import JSON
from ..drivers.asgi import HTMLResponse, JSONResponse, Request, Route, make_asgi_app
from ..drivers.http_server import HTTPServableApp
from ..utils.logging import Logger


class ProxyRoutes:
    GET_URSULAS = "get_ursulas"
    RETRIEVE_CFRAGS = "retrieve_cfrags"
    STATUS = "status"


class BaseProxyServer(ABC):
    """
    A base class for a stateful Porter -
    a service exposing node sampling/lookup via REST.
    """

    @abstractmethod
    async def start(self, nursery: trio.Nursery) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def get_ursulas(
        self, request_params: Mapping[str, str], request_body: JSON | None
    ) -> JSON: ...

    @abstractmethod
    async def retrieve_cfrags(self, request_body: JSON) -> JSON: ...

    @abstractmethod
    async def status(self) -> str: ...

    @abstractmethod
    def logger(self) -> Logger: ...


def make_proxy_asgi_app(server: BaseProxyServer) -> HTTPServableApp:
    """Returns an ASGI app serving as a front-end for a Proxy."""
    http_server = ProxyServerAsHTTPServer(server)
    return make_asgi_app(
        parent_logger=server.logger(),
        routes=[
            Route(ProxyRoutes.GET_URSULAS, ["GET"], http_server.get_ursulas),
            Route(ProxyRoutes.RETRIEVE_CFRAGS, ["POST"], http_server.retrieve_cfrags),
            Route(ProxyRoutes.STATUS, ["GET"], http_server.status),
        ],
        on_startup=http_server.start,
        on_shutdown=http_server.stop,
    )


class ProxyServerAsHTTPServer:
    def __init__(self, server: BaseProxyServer):
        self._server = server

    async def start(self, nursery: trio.Nursery) -> None:
        await self._server.start(nursery)

    async def stop(self, _nursery: trio.Nursery) -> None:
        await self._server.stop()

    async def get_ursulas(self, request: Request) -> JSONResponse:
        request_body = await request.body_json()  # TODO: add the query parameters here
        response = await self._server.get_ursulas(request.query_params, request_body)
        return JSONResponse(data=response)

    async def retrieve_cfrags(self, request: Request) -> JSONResponse:
        request_body = await request.body_json()
        response = await self._server.retrieve_cfrags(request_body)
        return JSONResponse(data=response)

    async def status(self, _request: Request) -> HTMLResponse:
        return HTMLResponse(page=await self._server.status())
