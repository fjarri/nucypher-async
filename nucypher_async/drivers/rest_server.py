from functools import partial
import os
from ssl import SSLContext
from typing import Optional

from hypercorn.config import Config
from hypercorn.trio import serve
import trio

from .rest_app import make_app
from .ssl import SSLCertificate, SSLPrivateKey
from ..utils import temp_file


class InMemoryCertificateConfig(Config):
    """
    Since Python's ssl bindings (which is what hypercorn uses)
    currently do not allow loading certificate/key from memory
    (see https://bugs.python.org/issue16487), we do this somewhat hacky workaround.
    """

    def __init__(self, ssl_certificate: SSLCertificate, ssl_private_key: SSLPrivateKey):
        super().__init__()
        self.__ssl_certificate = ssl_certificate

        # Have to keep the unencrypted private key in memory,
        # but at least we're not leaking it in the filesystem.
        # TODO: Can we do better? Zeroize it on cleanup?
        self.__ssl_private_key = ssl_private_key

    def create_ssl_context(self) -> Optional[SSLContext]:

        # sanity check
        if self.certfile or self.keyfile:
            raise RuntimeError(
                "Certificate/keyfile must be passed to the constructor in the serialized form")

        # Since ssl_enabled() returns True, the context will be created,
        # but with no certificates loaded.
        context = super().create_ssl_context()

        # Encrypt the temporary file we create with an emphemeral password.
        keyfile_password = os.urandom(32)

        with temp_file(self.__ssl_certificate.to_pem_bytes()) as certfile:
            with temp_file(self.__ssl_private_key.to_pem_bytes(keyfile_password)) as keyfile:
                context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=keyfile_password)

        return context

    @property
    def ssl_enabled(self) -> bool:
        return True


def make_config(ursula_server):

    config = InMemoryCertificateConfig(
        ssl_certificate=ursula_server._ssl_certificate,
        ssl_private_key=ursula_server._ssl_private_key)

    config.bind = [f"{ursula_server.ssl_contact.contact.host}:{ursula_server.ssl_contact.contact.port}"]
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


def start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(serve_async, ursula_server, shutdown_trigger=handle.shutdown_trigger()))
    return handle
