"""Encapsulates a specific HTTP server running our ASGI app (currently ``hypercorn``)."""

import os
from ssl import SSLContext
from typing import TYPE_CHECKING, cast

import hypercorn
import trio
from hypercorn.config import Config
from hypercorn.trio import serve

from ..utils import temp_file
from ..utils.ssl import SSLCertificate, SSLPrivateKey
from .peer import BasePeerServer

if TYPE_CHECKING:  # pragma: no cover
    import logging


class InMemoryCertificateConfig(Config):
    """
    Since Python's ssl bindings (which is what hypercorn uses)
    currently do not allow loading certificate/key from memory
    (see https://bugs.python.org/issue16487), we do this somewhat hacky workaround.
    """

    def __init__(
        self,
        ssl_certificate: SSLCertificate,
        ssl_private_key: SSLPrivateKey,
        ssl_ca_chain: list[SSLCertificate] | None,
    ):
        super().__init__()
        self.__ssl_certificate = ssl_certificate
        self.__ssl_ca_chain = ssl_ca_chain

        # Have to keep the unencrypted private key in memory,
        # but at least we're not leaking it in the filesystem.
        # TODO: Can we do better? Zeroize it on cleanup?
        self.__ssl_private_key = ssl_private_key

    def create_ssl_context(self) -> SSLContext | None:
        # sanity check
        if self.certfile or self.keyfile or self.ca_certs:
            raise RuntimeError(
                "Certificate/keyfile must be passed to the constructor in the serialized form"
            )

        context = super().create_ssl_context()

        # Since ssl_enabled() returns True, the context will be created,
        # but with no certificates loaded.
        assert context is not None, "SSL context was not created"

        # Encrypt the temporary file we create with an emphemeral password.
        keyfile_password = os.urandom(32)

        if self.__ssl_ca_chain:
            chain_data = b"\n".join(cert.to_pem_bytes() for cert in self.__ssl_ca_chain).decode()
            context.load_verify_locations(cadata=chain_data)

        with (
            temp_file(self.__ssl_certificate.to_pem_bytes()) as certfile,
            temp_file(self.__ssl_private_key.to_pem_bytes(keyfile_password)) as keyfile,
        ):
            context.load_cert_chain(certfile=certfile, keyfile=keyfile, password=keyfile_password)

        return context

    @property
    def ssl_enabled(self) -> bool:
        return True


def make_config(server: BasePeerServer) -> InMemoryCertificateConfig:
    config = InMemoryCertificateConfig(
        ssl_certificate=server.secure_contact().public_key._as_ssl_certificate(),  # noqa: SLF001
        ssl_private_key=server.peer_private_key()._as_ssl_private_key(),  # noqa: SLF001
        ssl_ca_chain=server.secure_contact().public_key._as_ssl_ca_chain(),  # noqa: SLF001
    )

    host, port = server.bind_pair()

    # Since the config accepts a class and not an instance of a logger,
    # we have to pass the parent logger through via an ad-hoc class.
    parent_logger = server.logger()

    class BoundLogger(hypercorn.logging.Logger):
        def __init__(self, config: Config):
            super().__init__(config)
            self.access_logger = None
            # Our logger has the same subset of `logging.Logger`'s API Hypercorn uses,
            # so we can safely cast.
            self.error_logger = cast("logging.Logger", parent_logger.get_child("HTTPServer"))

    config.bind = [f"{host}:{port}"]
    config.worker_class = "trio"
    config.logger_class = BoundLogger

    return config


class HTTPServerHandle:
    """
    A handle for a running web server.
    Can be used to shut it down.
    """

    def __init__(self, server: BasePeerServer):
        self.server = server
        self.app = server.into_servable()
        self._shutdown_event = trio.Event()
        self._shutdown_finished = trio.Event()

    async def startup(
        self, *, task_status: trio.TaskStatus[list[str]] = trio.TASK_STATUS_IGNORED
    ) -> None:
        """
        Starts the server in an external event loop.
        Useful for the cases when it needs to run in parallel with other servers or clients.

        Supports start-up reporting when invoked via `nursery.start()`.
        """
        config = make_config(self.server)
        await serve(
            self.app, config, shutdown_trigger=self._shutdown_event.wait, task_status=task_status
        )
        self._shutdown_finished.set()

    async def shutdown(self) -> None:
        self._shutdown_event.set()
        await self._shutdown_finished.wait()
