import trio

from .middleware import NetworkMiddleware
from .metadata import Metadata, FleetState
from .learner import Learner


class Ursula:

    def __init__(self, id):
        self.id = str(id)

    def metadata(self, address):
        return Metadata(id=self.id, address=address)


class HttpError(Exception):

    def __init__(self, message, status_code):
        super().__init__(message)
        self.status_code = status_code


class UrsulaServer:

    def __init__(self, ursula, middleware=None, port=9151, host='localhost', seed_addresses=[]):

        self.port = port
        self.host = host
        self.address = f"{host}:{port}"

        if middleware is None:
            middleware = NetworkMiddleware()

        self.ursula = ursula
        self.learner = Learner(middleware, self.ursula.metadata(self.address), seed_addresses)

        self.started = False

    def start(self, nursery):
        assert not self.started

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self.learner.start(nursery)

        self.started = True

    def stop(self):
        assert self.started

        self.learner.stop()

        self.started = False

    async def endpoint_ping(self):
        return self.ursula.metadata(self.address)

    async def endpoint_exchange_metadata(self, state: FleetState):
        await self.learner.remember_nodes(state)
        return self.learner.current_state()

    async def endpoint_reencrypt_dkg(self, capsule, key_bits):
        from .mock_nube.nube import KeyFrag, reencrypt
        kfrag = KeyFrag.from_bits(key_bits)
        cfrag = reencrypt(capsule, kfrag)
        return cfrag
