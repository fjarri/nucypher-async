import trio

from .certificate import SSLPrivateKey, SSLCertificate
from .middleware import NetworkMiddleware, HttpError
from .metadata import NodeID, Metadata, FleetState
from .learner import Learner
from .utils import BackgroundTask


class Ursula:

    def __init__(self):
        self.id = NodeID.random()


class UrsulaServer:

    def __init__(self, ursula, middleware=None, port=9151, host='127.0.0.1', seed_addresses=[]):

        self.port = port
        self.host = host
        self.address = f"{host}:{port}"

        # TODO: generate the seed from some root secret material.
        self.ssl_private_key = SSLPrivateKey.from_seed(b'asdasdasd')
        self.ssl_certificate = SSLCertificate.self_signed(self.ssl_private_key, self.host)

        if middleware is None:
            middleware = NetworkMiddleware()

        self.ursula = ursula
        self.learner = Learner(middleware, self.metadata(), seed_addresses)

        self.started = False

    def metadata(self):
        return Metadata(
            id=self.ursula.id,
            host=self.host,
            port=self.port,
            certificate=self.ssl_certificate)

    def start(self, nursery):
        assert not self.started

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._learning_task = BackgroundTask(nursery, self._learn)

        self.started = True

    async def _learn(self, this_task):
        try:
            with trio.fail_after(5):
                await self.learner.learning_round()
        except trio.TooSlowError:
            # Better luck next time
            pass
        except Exception as e:
            # TODO: log the error here
            pass
        await this_task.restart_in(10)

    def stop(self):
        assert self.started

        self._learning_task.stop()

        self.started = False

    async def endpoint_ping(self):
        return self.metadata().to_json()

    async def endpoint_exchange_metadata(self, state_json):
        state = FleetState.from_json(state_json)
        await self.learner.remember_nodes(state)
        return self.learner.current_state().to_json()

    async def endpoint_reencrypt_dkg(self, capsule, key_bits):
        from .mock_nube.nube import KeyFrag, reencrypt
        kfrag = KeyFrag.from_bits(key_bits)
        cfrag = reencrypt(capsule, kfrag)
        return cfrag
