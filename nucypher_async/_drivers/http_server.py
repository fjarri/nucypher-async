"""Encapsulates a specific HTTP server running our ASGI app (currently ``hypercorn``)."""

from abc import ABC, abstractmethod
from ipaddress import IPv4Address
from ssl import SSLContext
from typing import TYPE_CHECKING, TypeAlias, cast

import hypercorn
import trio
from hypercorn.config import Config
from hypercorn.trio import serve
from hypercorn.typing import ASGIFramework

from ..logging import Logger
from .ssl import SSLCertificate, SSLPrivateKey, fill_ssl_context

if TYPE_CHECKING:  # pragma: no cover
    import logging


HTTPServableApp: TypeAlias = ASGIFramework


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
        self.__ssl_private_key = ssl_private_key

    def create_ssl_context(self) -> SSLContext | None:
        context = super().create_ssl_context()

        # Since ssl_enabled() returns True, the context will be created,
        # but with no certificates loaded.
        assert context is not None, "SSL context was not created"

        fill_ssl_context(
            context, self.__ssl_private_key, self.__ssl_certificate, self.__ssl_ca_chain
        )

        return context

    @property
    def ssl_enabled(self) -> bool:
        return True


def make_config(server: "HTTPServable") -> InMemoryCertificateConfig:
    config = InMemoryCertificateConfig(
        ssl_certificate=server.ssl_certificate(),
        ssl_private_key=server.ssl_private_key(),
        ssl_ca_chain=server.ssl_ca_chain(),
    )

    address, port = server.bind_pair()

    logger = server.logger().get_child("HTTPServer")

    # Since the config accepts a class and not an instance of a logger,
    # we have to pass the parent logger through via an ad-hoc class.
    class BoundLogger(hypercorn.logging.Logger):
        def __init__(self, config: Config):
            super().__init__(config)
            self.access_logger = None
            # Our logger has the same subset of `logging.Logger`'s API Hypercorn uses,
            # so we can safely cast.
            self.error_logger = cast("logging.Logger", logger)

    config.bind = [f"{address}:{port}"]
    config.worker_class = "trio"
    config.logger_class = BoundLogger

    return config


class HTTPServable(ABC):
    @abstractmethod
    def bind_pair(self) -> tuple[IPv4Address, int]: ...

    @abstractmethod
    def logger(self) -> Logger: ...

    @abstractmethod
    def ssl_certificate(self) -> SSLCertificate: ...

    @abstractmethod
    def ssl_private_key(self) -> SSLPrivateKey: ...

    @abstractmethod
    def ssl_ca_chain(self) -> list[SSLCertificate]: ...


class HTTPServerHandle:
    """
    A handle for a running web server.
    Can be used to shut it down.
    """

    def __init__(self, server: HTTPServable, app: HTTPServableApp):
        self.server = server
        self.app = app
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
