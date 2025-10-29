"""
Encapsulates the specific ASGI framework
used to create an ASGI app out of server objects.

This is a thin layer that serves the following purposes:
- Extract request body and/or arguments and pass those to the server object's endpoint;
- wrap the returned raw data into a response;
- catch exceptions and wrap them in corresponding HTTP responses.

Nothing else should be happening here, the bulk of the server logic is located in server objects.
"""

import http
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import cast

import trio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..base.http_server import ASGIFramework
from ..base.peer_error import InactivePolicy, ServerSidePeerError
from ..base.porter import BasePorterServer, PorterRoutes
from ..base.types import JSON
from ..base.ursula import BaseUrsulaServer, UrsulaRoutes
from ..utils.logging import Logger

# HTTP status codes don't need to be unique or exhaustive, it's just an additional way
# to convey information to the user.
# The error type can be recovered from the status code in the JSON message.
_HTTP_STATUS = {
    InactivePolicy: http.HTTPStatus.PAYMENT_REQUIRED,
}


class HTTPError(Exception):
    def __init__(self, message: JSON, status_code: http.HTTPStatus):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


async def binary_api_call(logger: Logger, endpoint_future: Awaitable[bytes]) -> Response:
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


async def html_call(logger: Logger, endpoint_future: Awaitable[str]) -> Response:
    try:
        result = await endpoint_future
    except HTTPError as exc:
        return Response(exc.message, status_code=exc.status_code)
    except Exception as exc:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return Response(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)
    return Response(result)


async def rest_api_call(logger: Logger, endpoint_future: Awaitable[JSON]) -> Response:
    try:
        result = await endpoint_future
    except HTTPError as exc:
        return Response(exc.message, status_code=exc.status_code)
    except Exception as exc:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return Response(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)
    return JSONResponse(result)


def make_lifespan(
    on_startup: Callable[[trio.Nursery], Awaitable[None]],
    on_shutdown: Callable[[trio.Nursery], Awaitable[None]],
) -> Callable[[Starlette], AbstractAsyncContextManager[None]]:
    """
    A custom lifespan factory for Starlette that maintains a nursery
    in which background tasks can be run.
    """

    @asynccontextmanager
    async def lifespan_context(_app: Starlette) -> AsyncIterator[None]:
        async with trio.open_nursery() as nursery:
            await on_startup(nursery)
            yield
            await on_shutdown(nursery)

    return lifespan_context


def make_ursula_asgi_app(ursula_server: BaseUrsulaServer) -> ASGIFramework:
    """Returns an ASGI app serving as a front-end for a network peer (Ursula)."""
    logger = ursula_server.logger().get_child("App")

    async def ping(request: Request) -> Response:
        remote_host = request.client.host if request.client else None
        return await binary_api_call(logger, ursula_server.endpoint_ping(remote_host))

    async def node_metadata_get(_request: Request) -> Response:
        return await binary_api_call(logger, ursula_server.endpoint_node_metadata_get())

    async def node_metadata_post(request: Request) -> Response:
        remote_host = request.client.host if request.client else None
        request_bytes = await request.body()
        return await binary_api_call(
            logger,
            ursula_server.endpoint_node_metadata_post(remote_host, request_bytes),
        )

    async def public_information(_request: Request) -> Response:
        return await binary_api_call(logger, ursula_server.endpoint_public_information())

    async def reencrypt(request: Request) -> Response:
        request_bytes = await request.body()
        return await binary_api_call(logger, ursula_server.endpoint_reencrypt(request_bytes))

    async def decrypt(request: Request) -> Response:
        request_bytes = await request.body()
        return await binary_api_call(logger, ursula_server.endpoint_decrypt(request_bytes))

    async def status(request: Request) -> Response:
        # This is technically not a peer API, so we need special handling
        return await html_call(logger, ursula_server.endpoint_status())

    async def on_startup(nursery: trio.Nursery) -> None:
        await ursula_server.start(nursery)

    async def on_shutdown(_nursery: trio.Nursery) -> None:
        await ursula_server.stop()

    routes = [
        Route(f"/{UrsulaRoutes.PING}", ping),
        Route(f"/{UrsulaRoutes.NODE_METADATA}", node_metadata_get),
        Route(f"/{UrsulaRoutes.NODE_METADATA}", node_metadata_post, methods=["POST"]),
        Route(f"/{UrsulaRoutes.PUBLIC_INFORMATION}", public_information),
        Route(f"/{UrsulaRoutes.REENCRYPT}", reencrypt, methods=["POST"]),
        Route(f"/{UrsulaRoutes.DECRYPT}", decrypt, methods=["POST"]),
        Route(f"/{UrsulaRoutes.STATUS}", status),
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast("ASGIFramework", app)


def make_porter_asgi_app(porter_server: BasePorterServer) -> ASGIFramework:
    """Returns an ASGI app serving as a front-end for a Porter."""
    logger = porter_server.logger().get_child("App")

    async def get_ursulas(request: Request) -> Response:
        request_body = await request.json() if await request.body() else None
        return await rest_api_call(
            logger,
            porter_server.endpoint_get_ursulas(dict(request.query_params), request_body),
        )

    async def retrieve_cfrags(request: Request) -> Response:
        request_body = await request.json() if await request.body() else {}
        return await rest_api_call(logger, porter_server.endpoint_retrieve_cfrags(request_body))

    async def status(_request: Request) -> Response:
        return await html_call(logger, porter_server.endpoint_status())

    async def on_startup(nursery: trio.Nursery) -> None:
        await porter_server.start(nursery)

    async def on_shutdown(_nursery: trio.Nursery) -> None:
        await porter_server.stop()

    routes = [
        Route(f"/{PorterRoutes.GET_URSULAS}", get_ursulas),
        Route(f"/{PorterRoutes.RETRIEVE_CFRAGS}", retrieve_cfrags, methods=["POST"]),
        Route(f"/{PorterRoutes.STATUS}", status),
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast("ASGIFramework", app)
