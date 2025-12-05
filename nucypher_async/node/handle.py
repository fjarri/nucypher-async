from ipaddress import IPv4Address

import trio

from ..drivers.http_server import HTTPServable, HTTPServerHandle
from ..utils.logging import Logger
from ..utils.ssl import SSLCertificate, SSLPrivateKey
from .asgi_app import make_node_asgi_app
from .server import NodeServer


class NodeServerAsHTTPServer(HTTPServable):
    def __init__(self, node_server: NodeServer):
        self._node_server = node_server

    def bind_pair(self) -> tuple[IPv4Address, int]:
        return self._node_server.bind_pair()

    def logger(self) -> Logger:
        return self._node_server.logger()

    def ssl_certificate(self) -> SSLCertificate:
        return self._node_server.secure_contact().public_key._as_ssl_certificate()  # noqa: SLF001

    def ssl_private_key(self) -> SSLPrivateKey:
        return self._node_server.peer_private_key()._as_ssl_private_key()  # noqa: SLF001

    def ssl_ca_chain(self) -> list[SSLCertificate]:
        return []


class NodeServerHandle:
    """
    A handle for a running P2P server.
    Can be used to shut it down.
    """

    def __init__(self, server: NodeServer):
        self._handle = HTTPServerHandle(NodeServerAsHTTPServer(server), make_node_asgi_app(server))

    async def startup(
        self, *, task_status: trio.TaskStatus[list[str]] = trio.TASK_STATUS_IGNORED
    ) -> None:
        """
        Starts the server in an external event loop.
        Useful for the cases when it needs to run in parallel with other servers or clients.

        Supports start-up reporting when invoked via `nursery.start()`.
        """
        return await self._handle.startup(task_status=task_status)

    async def shutdown(self) -> None:
        return await self._handle.shutdown()
