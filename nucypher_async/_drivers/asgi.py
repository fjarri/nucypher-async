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
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import cast

import trio
from starlette.applications import Starlette
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.responses import Response as StarletteResponse
from starlette.routing import Route as StarletteRoute

from ..base.types import JSON
from ..utils.logging import Logger
from .http_server import HTTPServableApp


class HTTPError(Exception):
    def __init__(self, status_code: http.HTTPStatus, message: str):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


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


@dataclass
class BinaryResponse:
    data: bytes


@dataclass
class HTMLResponse:
    page: str


@dataclass
class JSONResponse:
    data: JSON


class Request:
    def __init__(self, request: StarletteRequest):
        self._request = request

    async def body_bytes(self) -> bytes:
        return await self._request.body()

    async def body_json(self) -> JSON:
        # Starlette reports the type as `Any`
        json = await self._request.json() if await self._request.body() else None
        return cast("JSON", json)

    @property
    def remote_host(self) -> str | None:
        # TODO: we can get the port here too
        return self._request.client.host if self._request.client else None

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.query_params


@dataclass
class Route:
    name: str
    methods: list[str]
    handler: Callable[[Request], Awaitable[BinaryResponse | HTMLResponse | JSONResponse]]


class RouteWrapper:
    def __init__(self, logger: Logger, route: Route):
        self._logger = logger
        self._route = route

    async def __call__(self, request: StarletteRequest) -> StarletteResponse:
        try:
            result = await self._route.handler(Request(request))
        except HTTPError as exc:
            return StarletteResponse(exc.message, status_code=exc.status_code)
        except Exception as exc:
            # A catch-all for any unexpected errors
            self._logger.error("Uncaught exception:", exc_info=True)
            return StarletteResponse(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)

        if isinstance(result, BinaryResponse):
            return StarletteResponse(result.data)
        if isinstance(result, JSONResponse):
            return StarletteJSONResponse(result.data)
        return StarletteResponse(result.page)


def make_asgi_app(
    parent_logger: Logger,
    routes: list[Route],
    on_startup: Callable[[trio.Nursery], Awaitable[None]],
    on_shutdown: Callable[[trio.Nursery], Awaitable[None]],
) -> HTTPServableApp:
    logger = parent_logger.get_child("App")

    # Starlette inspects the endpoint argument, and if it's a class instance,
    # it is treated differently (as an ASGI app).
    # So we need to give it the route method explicitly.
    starlette_routes = [
        StarletteRoute(
            f"/{route.name}", RouteWrapper(logger, route).__call__, methods=route.methods
        )
        for route in routes
    ]

    app = Starlette(lifespan=make_lifespan(on_startup, on_shutdown), routes=starlette_routes)

    # We don't have a typing package shared between Starlette and Hypercorn,
    # so this will have to do
    return cast("HTTPServableApp", app)
