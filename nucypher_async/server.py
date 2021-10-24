from functools import partial

from hypercorn.config import Config
from hypercorn.trio import serve
import trio

from .app import make_app


def make_config(ursula_server):
    config = Config()
    config.bind = [f"{ursula_server.host}:{ursula_server.port}"]
    config.worker_class = "trio"
    return config


async def serve_async(ursula_server, shutdown_trigger=None):
    config = make_config(ursula_server)
    app = make_app(ursula_server)
    await serve(app, config, shutdown_trigger=shutdown_trigger)


def serve_forever(ursula_server):
    trio.run(serve_async, ursula_server)


class ServerHandle:

    def __init__(self, ursula_server):
        self.ursula_server = ursula_server
        self._shutdown_event = trio.Event()

    def shutdown_trigger(self):
        return self._shutdown_event.wait

    def shutdown(self):
        self._shutdown_event.set()


async def mock_serve_async(nursery, ursula_server, shutdown_trigger):
    ursula_server.start(nursery)
    await shutdown_trigger()
    ursula_server.stop()


def mock_start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(mock_serve_async, nursery, ursula_server, shutdown_trigger=handle.shutdown_trigger()))
    return handle


def start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(serve_async, ursula_server, shutdown_trigger=handle.shutdown_trigger()))
    return handle
