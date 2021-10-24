from quart_trio import QuartTrio
from quart import make_response, request

from .ursula import UrsulaServer
from .metadata import FleetState


def make_app(ursula_server):
    """
    This is a thin layer that serves the following purposes:
    - wrap an UrsulaServer into an ASGI app (using Quart) that can be run in production;
    - deserialize requests, pass them to UrsulaServer, and serialize the return values.
    - catch exceptions and wrap them in fitting responses.
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
        metadata = await app.ursula_server.endpoint_ping()
        return await make_response(metadata.to_json())

    @app.route("/exchange_metadata", methods=['POST'])
    async def exchange_metadata():
        state_json = await request.json
        state = FleetState.from_json(state_json)
        new_state = await app.ursula_server.endpoint_exchange_metadata(state)
        return await make_response(new_state.to_json())

    return app
