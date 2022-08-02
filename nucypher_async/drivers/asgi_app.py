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

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
import trio

from ..base import PorterAPI, PeerAPI, PeerError, InactivePolicy


_HTTP_STATUS = {
    InactivePolicy: http.HTTPStatus.PAYMENT_REQUIRED
}


class HTTPError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message, status_code)
        self.message = message
        self.status_code = status_code


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


def make_lifespan(on_startup, on_shutdown):
    """
    A custom lifespan factory for Starlette that maintains a nursery
    in which background tasks can be run.
    """

    @asynccontextmanager
    async def lifespan_context(app):
        async with trio.open_nursery() as nursery:
            await on_startup(nursery)
            yield
            await on_shutdown(nursery)

    return lifespan_context


def make_peer_asgi_app(api: PeerAPI):
    """
    Returns an ASGI app serving as a front-end for a network peer (Ursula).
    """

    logger = api.logger().get_child('App')

    async def ping(request):
        return await peer_api_call(logger, api.endpoint_ping(request.client.host))

    async def node_metadata_get(request):
        return await peer_api_call(logger, api.endpoint_node_metadata_get())

    async def node_metadata_post(request):
        remote_host = request.client.host
        request_bytes = await request.body()
        return await peer_api_call(logger, api.endpoint_node_metadata_post(remote_host, request_bytes))

    async def public_information(request):
        return await peer_api_call(logger, api.endpoint_public_information())

    async def reencrypt(request):
        request_bytes = await request.body()
        return await peer_api_call(logger, api.endpoint_reencrypt(request_bytes))

    async def status(request):
        # This is technically not a peer API, so we need special handling
        return await rest_api_call(logger, api.endpoint_status())

    async def on_startup(nursery):
        await api.start(nursery)

    async def on_shutdown(nursery):
        await api.stop(nursery)

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


def make_porter_app(porter_server: PorterAPI):
    """
    Returns an ASGI app serving as a front-end for a Porter.
    """

    logger = porter_server.logger().get_child('App')

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

    async def on_shutdown(nursery):
        await porter_server.stop(nursery)

    routes = [
        Route("/get_ursulas", get_ursulas),
        Route("/retrieve_cfrags", retrieve_cfrags),
        Route("/status", status),
    ]

    app = Starlette(
        lifespan=make_lifespan(on_startup, on_shutdown),
        routes=routes)

    return app
