from typing import Dict, Tuple, Any, cast
from urllib.parse import urlparse

import httpx
import trio

from hypercorn.typing import (
    LifespanScope,
    LifespanShutdownEvent,
    LifespanStartupEvent,
    ASGIReceiveEvent,
    ASGISendEvent,
)

from ..base.http_server import BaseHTTPServer, ASGI3Framework
from ..utils.ssl import SSLCertificate


class LifespanManager:
    def __init__(self, app: ASGI3Framework):
        self.app = app
        self._send_channel, self._receive_channel = trio.open_memory_channel[ASGIReceiveEvent](0)
        self._startup_complete = trio.Event()
        self._shutdown_complete = trio.Event()

    async def run(self, nursery: trio.Nursery) -> None:
        lifespan: LifespanScope = {"type": "lifespan", "asgi": {"version": "3.0"}}
        nursery.start_soon(self.app, lifespan, self.receive, self.send)
        event: LifespanStartupEvent = {"type": "lifespan.startup"}
        await self._send_channel.send(event)
        await self._startup_complete.wait()

    async def shutdown(self) -> None:
        event: LifespanShutdownEvent = {"type": "lifespan.shutdown"}
        await self._send_channel.send(event)
        await self._shutdown_complete.wait()

    async def receive(self) -> ASGIReceiveEvent:
        return await self._receive_channel.receive()

    async def send(self, message: ASGISendEvent) -> None:
        if message["type"] == "lifespan.startup.complete":
            self._startup_complete.set()
        elif message["type"] == "lifespan.shutdown.complete":
            self._shutdown_complete.set()


class MockNetwork:
    def __init__(self, nursery: trio.Nursery):
        self.known_servers: Dict[Tuple[str, int], Tuple[SSLCertificate, LifespanManager]] = {}
        self.nursery = nursery

    def add_server(self, server: BaseHTTPServer) -> None:
        app = server.into_asgi_app()
        manager = LifespanManager(app)
        certificate = server.ssl_certificate()
        host, port = server.host_and_port()
        self.known_servers[(host, port)] = (certificate, manager)

    async def start_all(self) -> None:
        for _certificate, manager in self.known_servers.values():
            await manager.run(self.nursery)

    async def stop_all(self) -> None:
        for (_host, _port), (_certificate, manager) in self.known_servers.items():
            await manager.shutdown()


class MockHTTPClient:
    def __init__(self, mock_network: MockNetwork, host: str, certificate: SSLCertificate):
        # TODO: a weird separation here: the target host's certificate
        # is provided in the constructor, but then the target host can be selected
        # at will in `_request()`.
        self._mock_network = mock_network
        self._host = host
        self._certificate = certificate

    def as_httpx_async_client(self) -> httpx.AsyncClient:
        # We implement all the methods we need for it to act as one
        return cast(httpx.AsyncClient, self)

    async def get(self, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._request("get", url, *args, **kwargs)

    async def post(self, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        return await self._request("post", url, *args, **kwargs)

    async def _request(self, method: str, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        url_parts = urlparse(url)
        assert url_parts.hostname is not None, "Hostname is missing from the url"
        assert url_parts.port is not None, "Port is missing from the url"
        certificate, manager = self._mock_network.known_servers[
            (url_parts.hostname, url_parts.port)
        ]
        assert self._certificate == certificate
        transport = httpx.ASGITransport(app=manager.app, client=(self._host, 9999))
        async with httpx.AsyncClient(transport=transport) as client:
            return await client.request(method, url, *args, **kwargs)
