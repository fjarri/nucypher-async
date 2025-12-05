import http
import json
from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

import trio

from .._drivers.asgi import (
    BinaryResponse,
    HTMLResponse,
    HTTPError,
    JSONResponse,
    Request,
    Route,
    make_asgi_app,
)
from .._drivers.http_server import HTTPServableApp
from .._p2p import NodeRoutes, PeerError
from ._server import NodeServer


def make_node_asgi_app(server: NodeServer) -> HTTPServableApp:
    http_server = NodeServerAsHTTPServer(server)
    return make_asgi_app(
        parent_logger=server.logger(),
        routes=[
            Route(NodeRoutes.PING, ["GET"], http_server.ping),
            Route(NodeRoutes.NODE_METADATA, ["POST"], http_server.node_metadata),
            Route(NodeRoutes.PUBLIC_INFORMATION, ["GET"], http_server.public_information),
            Route(NodeRoutes.REENCRYPT, ["POST"], http_server.reencrypt),
            Route(NodeRoutes.CONDITION_CHAINS, ["GET"], http_server.condition_chains),
            Route(NodeRoutes.DECRYPT, ["POST"], http_server.decrypt),
            Route(NodeRoutes.STATUS, ["GET"], http_server.status),
        ],
        on_startup=http_server.start,
        on_shutdown=http_server.stop,
    )


Param = ParamSpec("Param")
RetVal = TypeVar("RetVal")


def wrap_peer_errors(func: Callable[Param, RetVal]) -> Callable[Param, RetVal]:
    @wraps(func)
    def wrapped(*args: Param.args, **kwds: Param.kwargs) -> RetVal:
        try:
            return func(*args, **kwds)
        except PeerError as exc:
            raise HTTPError(http.HTTPStatus.BAD_REQUEST, message=json.dumps(exc.to_json())) from exc

    return wrapped


class NodeServerAsHTTPServer:
    def __init__(self, server: NodeServer):
        self._server = server

    async def start(self, nursery: trio.Nursery) -> None:
        await self._server.start(nursery)

    async def stop(self, _nursery: trio.Nursery) -> None:
        await self._server.stop()

    @wrap_peer_errors
    async def ping(self, request: Request) -> BinaryResponse:
        return BinaryResponse(data=await self._server.ping(request.remote_host))

    @wrap_peer_errors
    async def node_metadata(self, request: Request) -> BinaryResponse:
        return BinaryResponse(
            data=await self._server.node_metadata(request.remote_host, await request.body_bytes())
        )

    @wrap_peer_errors
    async def public_information(self, _request: Request) -> BinaryResponse:
        return BinaryResponse(data=await self._server.public_information())

    @wrap_peer_errors
    async def reencrypt(self, request: Request) -> BinaryResponse:
        return BinaryResponse(data=await self._server.reencrypt(await request.body_bytes()))

    @wrap_peer_errors
    async def condition_chains(self, _request: Request) -> JSONResponse:
        return JSONResponse(data=await self._server.condition_chains())

    @wrap_peer_errors
    async def decrypt(self, request: Request) -> BinaryResponse:
        return BinaryResponse(data=await self._server.decrypt(await request.body_bytes()))

    async def status(self, _request: Request) -> HTMLResponse:
        return HTMLResponse(page=await self._server.status())
