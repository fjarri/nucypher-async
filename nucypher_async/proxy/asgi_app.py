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
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import cast

import trio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..base.types import JSON
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
    async def endpoint_get_ursulas(
        self, request_params: dict[str, str], request_body: JSON | None
    ) -> JSON: ...

    @abstractmethod
    async def endpoint_retrieve_cfrags(self, request_body: JSON) -> JSON: ...

    @abstractmethod
    async def endpoint_status(self) -> str: ...

    @abstractmethod
    def logger(self) -> Logger: ...


class HTTPError(Exception):
    def __init__(self, message: str, status_code: http.HTTPStatus):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


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


def make_proxy_asgi_app(proxy_server: BaseProxyServer) -> HTTPServableApp:
    """Returns an ASGI app serving as a front-end for a Proxy."""
    logger = proxy_server.logger().get_child("App")

    async def get_ursulas(request: Request) -> Response:
        request_body = await request.json() if await request.body() else None
        return await rest_api_call(
            logger,
            proxy_server.endpoint_get_ursulas(dict(request.query_params), request_body),
        )

    async def retrieve_cfrags(request: Request) -> Response:
        request_body = await request.json() if await request.body() else {}
        return await rest_api_call(logger, proxy_server.endpoint_retrieve_cfrags(request_body))

    async def status(_request: Request) -> Response:
        return await html_call(logger, proxy_server.endpoint_status())

    async def on_startup(nursery: trio.Nursery) -> None:
        await proxy_server.start(nursery)

    async def on_shutdown(_nursery: trio.Nursery) -> None:
        await proxy_server.stop()

    routes = [
        Route(f"/{ProxyRoutes.GET_URSULAS}", get_ursulas),
        Route(f"/{ProxyRoutes.RETRIEVE_CFRAGS}", retrieve_cfrags, methods=["POST"]),
        Route(f"/{ProxyRoutes.STATUS}", status),
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast("HTTPServableApp", app)
