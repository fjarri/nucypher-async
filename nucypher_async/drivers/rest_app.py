"""
This module encapsulates the specific package used to create an ASGI app
out of ``UrsulaServer`` (namely, Quart).

This is a thin layer that serves the following purposes:
- pass raw data from requests made to the app to ``UrsulaServer``;
- wrap the returned raw data into a response;
- catch ``HTTPError`` from ``UrsulaServer`` and wrap them in corresponding responses.
Nothing else should be happening here, the bulk of the server logic
is located in ``UrsulaServer``.

In a sense, this is a "server" counterpart of ``rest_client``.
"""

import http
import sys

from quart_trio import QuartTrio
from quart import make_response, request

from .rest_client import HTTPError


async def wrap_in_response(logger, callable, *args, **kwds):
    try:
        result = await callable(*args, **kwds)
    # TODO: we can have a small subset of errors here that are a part of the protocol,
    # and correspond to HTTP status codes
    except HTTPError as e:
        return await make_response(e.args[0], e.status_code)
    except Exception as e:
        # A catch-all for any unexpected errors
        logger.error("Uncaught exception:", exc_info=True)
        return await make_response(str(e), http.HTTPStatus.INTERNAL_SERVER_ERROR)
    return await make_response(result)


def make_ursula_app(ursula_server):
    """
    Creates and returns an ASGI app.
    """

    # Since we need to use an externally passed context in the app (``ursula_server``),
    # we have to create the app inside a function.

    app = QuartTrio('ursula_async')

    # TODO: this is a little backwards; the app encompasses UrsulaServer,
    # but this new logger is a child of UrsulaServer's logger.
    # Is there a more logical way to create a logger?
    logger = ursula_server._logger.get_child('App')

    @app.before_serving
    async def on_startup():
        await ursula_server.start(app.nursery)

    @app.after_serving
    async def on_shutdown():
        ursula_server.stop()

    @app.route("/ping")
    async def ping():
        return await wrap_in_response(logger, ursula_server.endpoint_ping, request.remote_addr)

    @app.route("/node_metadata")
    async def node_metadata_get():
        return await wrap_in_response(logger, ursula_server.endpoint_node_metadata_get)

    @app.route("/node_metadata", methods=['POST'])
    async def node_metadata_post():
        metadata_request_bytes = await request.data
        return await wrap_in_response(
            logger, ursula_server.endpoint_node_metadata_post,
            request.remote_addr, metadata_request_bytes)

    @app.route("/public_information")
    async def public_information():
        return await wrap_in_response(logger, ursula_server.endpoint_public_information)

    @app.route("/reencrypt", methods=["POST"])
    async def reencrypt():
        reencryption_request_bytes = await request.data
        return await wrap_in_response(logger, ursula_server.endpoint_reencrypt, reencryption_request_bytes)

    @app.route("/status")
    async def status():
        return await wrap_in_response(logger, ursula_server.endpoint_status)

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
        return await wrap_in_response(logger, porter_server.endpoint_get_ursulas, get_ursulas_request)

    @app.route("/retrieve_cfrags", methods=['POST'])
    async def retrieve_cfrags():
        retrieve_cfrags_request = await request.json
        return await wrap_in_response(logger, porter_server.endpoint_retrieve_cfrags, retrieve_cfrags_request)

    @app.route("/status")
    async def status():
        return await wrap_in_response(logger, porter_server.endpoint_status)

    return app
