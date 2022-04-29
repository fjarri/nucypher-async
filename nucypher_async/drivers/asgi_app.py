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
import http
import sys

from quart_trio import QuartTrio
from quart import make_response, request

from ..peer_api import PeerRequest, PeerAPI


class HTTPError(ABC, Exception):

    @abstractmethod
    def serialize(self) -> (str, http.HTTPStatus):
        ...


async def call_endpoint(endpoint_future):
    try:
        result_bytes = await endpoint_future
    except HTTPError as exc:
        return exc.serialize()
    return result_bytes, http.HTTPStatus.OK


async def wrap_in_response(logger, endpoint_future):
    try:
        result_bytes, status_code = await call_endpoint(endpoint_future)
    except Exception as e:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return await make_response(str(e), http.HTTPStatus.INTERNAL_SERVER_ERROR)
    return await make_response(result_bytes, status_code)


class QuartRequest(PeerRequest):

    @classmethod
    async def from_contextvar(cls):
        return cls(request.remote_addr, await request.get_data(cache=False))

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

    # Since we need to use an externally passed context in the app (``ursula_server``),
    # we have to create the app inside a function.

    app = QuartTrio('ursula_async')

    logger = api.logger().get_child('App')

    @app.before_serving
    async def on_startup():
        await api.start(app.nursery)

    @app.after_serving
    async def on_shutdown():
        await api.stop()

    @app.route("/ping")
    async def ping():
        req = await QuartRequest.from_contextvar()
        return await wrap_in_response(logger, api.endpoint_ping(req))

    @app.route("/node_metadata")
    async def node_metadata_get():
        req = await QuartRequest.from_contextvar()
        return await wrap_in_response(logger, api.endpoint_node_metadata_get(req))

    @app.route("/node_metadata", methods=['POST'])
    async def node_metadata_post():
        req = await QuartRequest.from_contextvar()
        return await wrap_in_response(logger, api.endpoint_node_metadata_post(req))

    @app.route("/public_information")
    async def public_information():
        req = await QuartRequest.from_contextvar()
        return await wrap_in_response(logger, api.endpoint_public_information(req))

    @app.route("/reencrypt", methods=["POST"])
    async def reencrypt():
        req = await QuartRequest.from_contextvar()
        return await wrap_in_response(logger, api.endpoint_reencrypt(req))

    @app.route("/status")
    async def status():
        return await wrap_in_response(logger, api.endpoint_status())

    return app


def make_porter_app(porter_server):

    app = QuartTrio('porter_async')

    logger = porter_server._logger.get_child('App')

    @app.before_serving
    async def on_startup():
        await porter_server.start(app.nursery)

    @app.after_serving
    async def on_shutdown():
        porter_server.stop()

    @app.route('/get_ursulas')
    async def get_ursulas():
        get_ursulas_request = await request.json or {}
        get_ursulas_request.update(request.args)
        return await wrap_in_response(logger, porter_server.endpoint_get_ursulas(get_ursulas_request))

    @app.route("/retrieve_cfrags", methods=['POST'])
    async def retrieve_cfrags():
        retrieve_cfrags_request = await request.json
        return await wrap_in_response(logger, porter_server.endpoint_retrieve_cfrags(retrieve_cfrags_request))

    @app.route("/status")
    async def status():
        return await wrap_in_response(logger, porter_server.endpoint_status())

    return app
