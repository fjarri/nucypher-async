"""
This module encapsulates the specific package used to create an ASGI app
out of ``UrsulaServer`` (namely, Quart).

This is a thin layer that serves the following purposes:
- pass raw data from requests made to the app to ``UrsulaServer``;
- wrap the returned raw data into a response;
- catch ``RPCError`` from ``UrsulaServer`` and wrap them in corresponding responses.
Nothing else should be happening here, the bulk of the server logic
is located in ``UrsulaServer``.

In a sense, this is a "server" counterpart of ``PeerClient``.
"""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import http
import sys

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import trio

from ..peer_api import PeerRequest, PeerAPI, PeerError, InactivePolicy


_HTTP_STATUS = {
    InactivePolicy: http.HTTPStatus.PAYMENT_REQUIRED
}


async def call_endpoint(endpoint_future):
    try:
        result_bytes = await endpoint_future
    except PeerError as exc:
        message = exc.to_json()
        status = http.HTTPStatus.INTERNAL_SERVER_ERROR
        for tp, code in _HTTP_STATUS:
            if isinstance(exc, tp):
                status = code
                break
        return message, status

    return result_bytes, http.HTTPStatus.OK


async def peer_api_call(logger, endpoint_future):
    try:
        result_bytes, status_code = await call_endpoint(endpoint_future)
    except Exception as exc:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return Response(str(exc), status_code=http.HTTPStatus.INTERNAL_SERVER_ERROR)
    return Response(result_bytes, status_code=status_code)


def make_lifespan(on_startup, on_shutdown):

    @asynccontextmanager
    async def lifespan_context(app):
        async with trio.open_nursery() as nursery:
            await on_startup(nursery)
            yield
            await on_shutdown()

    return lifespan_context


class StarletteRequest(PeerRequest):

    @classmethod
    async def from_request(cls, request):
        return cls(request.client.host, await request.body())

    def __init__(self, remote_host, data):
        self._remote_host = remote_host
        self._data = data

    def remote_host(self):
        return self._remote_host

    def data(self):
        return self._data


def make_peer_asgi_app(api: PeerAPI):
    """
    Creates and returns an ASGI app.
    """

    logger = api.logger().get_child('App')

    async def ping(request):
        req = await StarletteRequest.from_request(request)
        return await peer_api_call(logger, api.endpoint_ping(req))

    async def node_metadata_get(request):
        req = await StarletteRequest.from_request(request)
        return await peer_api_call(logger, api.endpoint_node_metadata_get(req))

    async def node_metadata_post(request):
        req = await StarletteRequest.from_request(request)
        return await peer_api_call(logger, api.endpoint_node_metadata_post(req))

    async def public_information(request):
        req = await StarletteRequest.from_request(request)
        return await peer_api_call(logger, api.endpoint_public_information(req))

    async def reencrypt(request):
        req = await StarletteRequest.from_request(request)
        return await peer_api_call(logger, api.endpoint_reencrypt(req))

    async def status(request):
        # This is technically not a peer API, so we need special handling
        return await rest_api_call(logger, api.endpoint_status())

    async def on_startup(nursery):
        await api.start(nursery)

    async def on_shutdown():
        await api.stop()

    routes = [
        Route("/ping", ping),
        Route("/node_metadata", node_metadata_get),
        Route("/node_metadata", node_metadata_post, methods=["POST"]),
        Route("/public_information", public_information),
        Route("/reencrypt", reencrypt, methods=["POST"]),
        Route("/status", status),
    ]

    app = Starlette(
        lifespan=make_lifespan(on_startup, on_shutdown),
        routes=routes)

    return app


class HTTPError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


async def rest_api_call(logger, endpoint_future):
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


def make_porter_app(porter_server):

    logger = porter_server._logger.get_child('App')

    async def get_ursulas(request):
        json_request = await request.json() if await request.body() else {}
        json_request.update(request.query_params)
        return await rest_api_call(logger, porter_server.endpoint_get_ursulas(json_request))

    async def retrieve_cfrags(request):
        json_request = await request.json() if await request.body() else {}
        json_request.update(request.query_params)
        return await rest_api_call(logger, porter_server.endpoint_retrieve_cfrags(json_request))

    async def status(request):
        return await rest_api_call(logger, porter_server.endpoint_status())

    async def on_startup(nursery):
        await porter_server.start(nursery)

    async def on_shutdown():
        await porter_server.stop()

    routes = [
        Route("/get_ursulas", get_ursulas),
        Route("/retrieve_cfrags", retrieve_cfrags),
        Route("/status", status),
    ]

    app = Starlette(
        lifespan=make_lifespan(on_startup, on_shutdown),
        routes=routes)

    return app
