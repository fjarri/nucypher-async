"""Encapsulates a specific HTTP server running our ASGI app (currently ``hypercorn``)."""

import os
from ssl import SSLContext
from typing import cast

import trio
from hypercorn.config import Config
from hypercorn.trio import serve

from ..base.http_server import BaseHTTPServer
from ..utils import temp_file
from ..utils.ssl import SSLCertificate, SSLPrivateKey


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


def make_config(server: BaseHTTPServer) -> InMemoryCertificateConfig:
    config = InMemoryCertificateConfig(
        ssl_certificate=server.ssl_certificate(),
        ssl_private_key=server.ssl_private_key(),
        ssl_ca_chain=server.ssl_ca_chain(),
    )

    host, port = server.host_and_port()

    config.bind = [f"{host}:{port}"]
    config.worker_class = "trio"

    return config


class HTTPServerHandle:
    """
    A handle for a running web server.
    Can be used to shut it down.
    """

    def __init__(self, server: BaseHTTPServer):
        self.server = server
        self.app = server.into_asgi_app()
        self._shutdown_event = trio.Event()
        self._shutdown_finished = trio.Event()

    async def startup(
        self, *, task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED
    ) -> None:
        """
        Starts the server in an external event loop.
        Useful for the cases when it needs to run in parallel with other servers or clients.

        Supports start-up reporting when invoked via `nursery.start()`.
        """
        config = make_config(self.server)
        await serve(
            self.app,
            config,
            shutdown_trigger=self._shutdown_event.wait,
            # That's what hypercorn API declares, but it's the same type as `trio.TaskStatus`
            task_status=cast("trio._core._run._TaskStatus", task_status),  # noqa: SLF001
        )
        self._shutdown_finished.set()

    async def shutdown(self) -> None:
        self._shutdown_event.set()
        await self._shutdown_finished.wait()
