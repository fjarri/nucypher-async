from quart_trio import QuartTrio
from quart import make_response, request

from .errors import HTTPError


async def wrap_in_response(callable, *args, **kwds):
    try:
        result_json = await callable(*args, **kwds)
    # TODO: we can have a small subset of errors here that are a part of the protocol,
    # and correspond to HTTP status codes
    except HTTPError as e:
        return await make_response((str(e), e.status_code))
    return await make_response(result_json)


def make_app(ursula_server):
    """
    This is a thin layer that serves the following purposes:
    - wrap an UrsulaServer into an ASGI app (using Quart) that can be run in production;
    - pass raw data from requests to UrsulaServer;
    - wrap the returned raw data into a response;
    - catch HTTPError and wrap them in corresponding responses.
    Nothing else should be happening here, the bulk of the server logic is located in UrsulaServer.

    In a sense, this is a "server" counterpart of NetworkMiddleware.
    """

    app = QuartTrio('ursula_async')
    app.ursula_server = ursula_server

    @app.before_serving
    async def on_startup():
        app.ursula_server.start(app.nursery)

    @app.after_serving
    async def on_shutdown():
        app.ursula_server.stop()

    @app.route("/ping")
    async def ping():
        return await wrap_in_response(app.ursula_server.endpoint_ping)

    @app.route("/get_contacts", methods=['POST'])
    async def get_contacts():
        signed_contact_json = await request.json
        return await wrap_in_response(app.ursula_server.endpoint_get_contacts)

    return app
