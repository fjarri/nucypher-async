"""
This module encapsulates the specific ASGI framework
used to create an ASGI app out of server objects.

This is a thin layer that serves the following purposes:
- Extract request body and/or arguments and pass those to the server object's endpoint;
- wrap the returned raw data into a response;
- catch exceptions and wrap them in corresponding HTTP responses.

Nothing else should be happening here, the bulk of the server logic is located in server objects.
"""

from contextlib import asynccontextmanager
import http
from typing import Callable, Awaitable, AsyncIterator, AsyncContextManager, cast

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import trio
from hypercorn.typing import (
    LifespanScope,
    LifespanShutdownEvent,
    LifespanStartupEvent,
    ASGIReceiveEvent,
    ASGISendEvent,
)

from ..base.http_server import ASGI3Framework
from ..base.peer import BasePeer, ServerSidePeerError, InactivePolicy
from ..base.porter import BasePorter
from ..utils.logging import Logger


# HTTP status codes don't need to be unique or exhaustive, it's just an additional way
# to convey information to the user.
# The error type can be recovered from the status code in the JSON message.
_HTTP_STATUS = {
    InactivePolicy: http.HTTPStatus.PAYMENT_REQUIRED,
}


class HTTPError(Exception):
    def __init__(self, message: str, status_code: http.HTTPStatus):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


async def peer_api_call(logger: Logger, endpoint_future: Awaitable[bytes]) -> Response:
    try:
        result_bytes = await endpoint_future
    except ServerSidePeerError as exc:
        message = exc.to_json()
        status_code = http.HTTPStatus.INTERNAL_SERVER_ERROR
        for tp, code in _HTTP_STATUS.items():
            if isinstance(exc, tp):
                status_code = code
                break
        return JSONResponse(message, status_code=status_code)
    except Exception as exc:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return Response(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)

    return Response(result_bytes)


async def rest_api_call(logger: Logger, endpoint_future: Awaitable[str]) -> Response:
    try:
        result_str = await endpoint_future
    except HTTPError as exc:
        return Response(exc.message, status_code=exc.status_code)
    except Exception as exc:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return Response(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)
    if isinstance(result_str, str):
        return Response(result_str)
    else:
        return JSONResponse(result_str)


def make_lifespan(
    on_startup: Callable[[trio.Nursery], Awaitable[None]],
    on_shutdown: Callable[[trio.Nursery], Awaitable[None]],
) -> Callable[[Starlette], AsyncContextManager[None]]:
    """
    A custom lifespan factory for Starlette that maintains a nursery
    in which background tasks can be run.
    """

    @asynccontextmanager
    async def lifespan_context(app: Starlette) -> AsyncIterator[None]:
        async with trio.open_nursery() as nursery:
            await on_startup(nursery)
            yield
            await on_shutdown(nursery)

    return lifespan_context


def make_peer_asgi_app(peer: BasePeer) -> ASGI3Framework:
    """
    Returns an ASGI app serving as a front-end for a network peer (Ursula).
    """

    logger = peer.logger().get_child("App")

    async def ping(request: Request) -> Response:
        remote_host = request.client.host if request.client else None
        return await peer_api_call(logger, peer.endpoint_ping(remote_host))

    async def node_metadata_get(request: Request) -> Response:
        return await peer_api_call(logger, peer.endpoint_node_metadata_get())

    async def node_metadata_post(request: Request) -> Response:
        remote_host = request.client.host if request.client else None
        request_bytes = await request.body()
        return await peer_api_call(
            logger, peer.endpoint_node_metadata_post(remote_host, request_bytes)
        )

    async def public_information(request: Request) -> Response:
        return await peer_api_call(logger, peer.endpoint_public_information())

    async def reencrypt(request: Request) -> Response:
        request_bytes = await request.body()
        return await peer_api_call(logger, peer.endpoint_reencrypt(request_bytes))

    async def status(request: Request) -> Response:
        # This is technically not a peer API, so we need special handling
        return await rest_api_call(logger, peer.endpoint_status())

    async def on_startup(nursery: trio.Nursery) -> None:
        await peer.start(nursery)

    async def on_shutdown(nursery: trio.Nursery) -> None:
        await peer.stop(nursery)

    routes = [
        Route("/ping", ping),
        Route("/node_metadata", node_metadata_get),
        Route("/node_metadata", node_metadata_post, methods=["POST"]),
        Route("/public_information", public_information),
        Route("/reencrypt", reencrypt, methods=["POST"]),
        Route("/status", status),
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast(ASGI3Framework, app)


def make_porter_app(porter: BasePorter) -> ASGI3Framework:
    """
    Returns an ASGI app serving as a front-end for a Porter.
    """

    logger = porter.logger().get_child("App")

    async def get_ursulas(request: Request) -> Response:
        json_request = await request.json() if await request.body() else {}
        json_request.update(request.query_params)
        return await rest_api_call(logger, porter.endpoint_get_ursulas(json_request))

    async def retrieve_cfrags(request: Request) -> Response:
        json_request = await request.json() if await request.body() else {}
        json_request.update(request.query_params)
        return await rest_api_call(logger, porter.endpoint_retrieve_cfrags(json_request))

    async def status(request: Request) -> Response:
        return await rest_api_call(logger, porter.endpoint_status())

    async def on_startup(nursery: trio.Nursery) -> None:
        await porter.start(nursery)

    async def on_shutdown(nursery: trio.Nursery) -> None:
        await porter.stop(nursery)

    routes = [
        Route("/get_ursulas", get_ursulas),
        Route("/retrieve_cfrags", retrieve_cfrags),
        Route("/status", status),
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast(ASGI3Framework, app)
