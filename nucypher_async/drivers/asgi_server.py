"""
This module encapsulates a specific server running our ASGI app (currently ``hypercorn``).
"""

from abc import ABC, abstractmethod
from functools import partial
import os
from ssl import SSLContext
from typing import Optional

from hypercorn.config import Config
from hypercorn.trio import serve
import trio

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


class ASGIServer(ABC):

    @abstractmethod
    def host_and_port(self) -> (str, int):
        ...

    @abstractmethod
    def ssl_certificate(self) -> SSLCertificate:
        ...

    @abstractmethod
    def ssl_private_key(self) -> SSLPrivateKey:
        ...

    @abstractmethod
    def into_asgi_app(self):
        ...


def make_config(server: ASGIServer):

    secure_contact = server.secure_contact()

    config = InMemoryCertificateConfig(
        ssl_certificate=server.ssl_certificate(),
        ssl_private_key=server.ssl_private_key())

    host, port = server.host_and_port()

    config.bind = [f"{host}:{port}"]
    config.worker_class = "trio"

    return config


class ASGIServerHandle:
    """
    A handle for a running web server.
    Can be used to shut it down.
    """

    def __init__(self, server: ASGIServer):
        self.server = server
        self._shutdown_event = trio.Event()

    async def __call__(self, *, task_status=trio.TASK_STATUS_IGNORED):
        """
        Starts the server in an external event loop.
        Useful for the cases when it needs to run in parallel with other servers or clients.

        Supports start-up reporting when invoked via `nursery.start()`.
        """
        config = make_config(self.server)
        app = self.server.into_asgi_app()
        await serve(app, config, shutdown_trigger=self._shutdown_event.wait, task_status=task_status)

    def shutdown(self):
        self._shutdown_event.set()


def serve_forever(server: ASGIServer):
    """
    Runs the Ursula web server and blocks.
    """
    trio.run(ASGIServerHandle(server))
