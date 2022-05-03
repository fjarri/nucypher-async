from contextlib import asynccontextmanager
from typing import NamedTuple
from urllib.parse import urlparse
import weakref

import httpx
import trio
from nucypher_async.drivers.ssl import SSLCertificate
from nucypher_async.drivers.asgi_server import ASGIServer


class LifespanManager:

    def __init__(self, app):
        self.app = app
        self._send_channel, self._receive_channel = trio.open_memory_channel(0)
        self._startup_complete = trio.Event()
        self._shutdown_complete = trio.Event()

    async def run(self, nursery):
        nursery.start_soon(self.app, {"type": "lifespan"}, self.receive, self.send)
        await self._send_channel.send({"type": "lifespan.startup"})
        await self._startup_complete.wait()

    async def shutdown(self):
        await self._send_channel.send({"type": "lifespan.shutdown"})
        await self._shutdown_complete.wait()

    async def receive(self):
        return await self._receive_channel.receive()

    async def send(self, message):
        if message["type"] == "lifespan.startup.complete":
            self._startup_complete.set()
        elif message["type"] == "lifespan.shutdown.complete":
            self._shutdown_complete.set()


class MockNetwork:

    def __init__(self, nursery):
        self.known_servers = {}
        self.nursery = nursery

    def add_server(self, server: ASGIServer):
        app = server.into_asgi_app()
        manager = LifespanManager(app)
        certificate = server.ssl_certificate()
        host, port = server.host_and_port()
        self.known_servers[(host, port)] = (certificate, manager)

    async def start_all(self):
        for certificate, manager in self.known_servers.values():
            await manager.run(self.nursery)

    async def stop_all(self):
        for certificate, manager in self.known_servers.values():
            await manager.shutdown()


class MockHTTPClient:

    def __init__(self, mock_network, host, certificate):
        self._mock_network = mock_network
        self._host = host
        self._certificate = certificate

    async def get(self, url, *args, **kwargs):
        return await self._request("get", url, *args, **kwargs)

    async def post(self, url, *args, **kwargs):
        return await self._request("post", url, *args, **kwargs)

    async def _request(self, method, url, *args, **kwargs):
        url_parts = urlparse(url)
        certificate, manager = self._mock_network.known_servers[(url_parts.hostname, url_parts.port)]
        assert self._certificate == certificate
        transport = httpx.ASGITransport(app=manager.app, client=(self._host, 9999))
        async with httpx.AsyncClient(transport=transport) as client:
            return await client.request(method, url, *args, **kwargs)
