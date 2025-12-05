import trio

from .._drivers.http_server import HTTPServerHandle
from ._asgi_app import make_proxy_asgi_app
from ._server import ProxyServer


class ProxyServerHandle:
    """
    A handle for a running Proxy server.
    Can be used to shut it down.
    """

    def __init__(self, server: ProxyServer):
        self._handle = HTTPServerHandle(server, make_proxy_asgi_app(server))

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
