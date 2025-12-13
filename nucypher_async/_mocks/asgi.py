from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any, cast
from urllib.parse import urlparse

import httpx
import trio
from hypercorn.typing import (
    ASGIFramework,
    ASGIReceiveEvent,
    ASGISendEvent,
    LifespanScope,
    LifespanShutdownEvent,
    LifespanStartupEvent,
)

from .._drivers.http_client import HTTPClient, HTTPClientError, HTTPClientSession, HTTPResponse
from .._drivers.http_server import HTTPServable, HTTPServableApp
from .._drivers.ssl import SSLCertificate
from ..proxy import ProxyServer
from ..proxy._asgi_app import make_proxy_asgi_app


class LifespanManager:
    def __init__(self, app: ASGIFramework):
        self.app = app
        self._send_channel, self._receive_channel = trio.open_memory_channel[ASGIReceiveEvent](0)
        self._startup_complete = trio.Event()
        self._shutdown_complete = trio.Event()

    async def startup(self, nursery: trio.Nursery) -> None:
        lifespan: LifespanScope = {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}
        nursery.start_soon(self.app, lifespan, self._receive, self._send)
        event: LifespanStartupEvent = {"type": "lifespan.startup"}
        await self._send_channel.send(event)
        await self._startup_complete.wait()

    async def shutdown(self) -> None:
        event: LifespanShutdownEvent = {"type": "lifespan.shutdown"}
        await self._send_channel.send(event)
        await self._shutdown_complete.wait()

    async def _receive(self) -> ASGIReceiveEvent:
        return await self._receive_channel.receive()

    async def _send(self, message: ASGISendEvent) -> None:
        if message["type"] == "lifespan.startup.complete":
            self._startup_complete.set()
        elif message["type"] == "lifespan.shutdown.complete":
            self._shutdown_complete.set()


class MockHTTPServerHandle:
    def __init__(self, network: "MockHTTPNetwork", host: str, port: int):
        self._network = network
        self._host = host
        self._port = port

    async def startup(self) -> None:
        await self._network.startup(self._host, self._port)

    async def shutdown(self) -> None:
        await self._network.shutdown(self._host, self._port)


class MockHTTPNetwork:
    def __init__(self, nursery: trio.Nursery):
        self._known_servers: dict[tuple[str, int], tuple[SSLCertificate, LifespanManager]] = {}
        self._nursery = nursery

    def add_proxy_server(self, server: ProxyServer) -> MockHTTPServerHandle:
        return self.add_server(server, make_proxy_asgi_app(server))

    def add_server(self, server: HTTPServable, app: HTTPServableApp) -> MockHTTPServerHandle:
        manager = LifespanManager(app)
        certificate = server.ssl_certificate()
        host, port = server.bind_pair()
        str_host = str(host)
        assert (str_host, port) not in self._known_servers
        self._known_servers[(str_host, port)] = (certificate, manager)
        return MockHTTPServerHandle(self, str_host, port)

    async def startup(self, host: str, port: int) -> None:
        _certificate, manager = self._known_servers[(host, port)]
        await manager.startup(self._nursery)

    async def shutdown(self, host: str, port: int) -> None:
        _certificate, manager = self._known_servers[(host, port)]
        await manager.startup(self._nursery)

    def get_server(self, host: str, port: int) -> tuple[SSLCertificate, LifespanManager]:
        return self._known_servers[(host, port)]


class MockHTTPClient(HTTPClient):
    def __init__(self, mock_network: MockHTTPNetwork, client_host: str | None = None):
        self._mock_network = mock_network
        # Since the nodes use HTTP for P2P messaging,
        # we need to be able to report the client's hostname (used for DDoS protection).
        self._client_host = client_host or "passive client"

    async def fetch_certificate(self, host: str, port: int) -> SSLCertificate:
        certificate, _manager = self._mock_network.get_server(host, port)
        return certificate

    @asynccontextmanager
    async def session(
        self, certificate: SSLCertificate | None = None
    ) -> AsyncIterator["MockHTTPClientSession"]:
        yield MockHTTPClientSession(self._mock_network, self._client_host, certificate)


class MockHTTPClientSession(HTTPClientSession):
    def __init__(
        self,
        mock_network: MockHTTPNetwork,
        client_host: str = "mock_hostname",
        certificate: SSLCertificate | None = None,
    ):
        self._mock_network = mock_network
        self._client_host = client_host
        self._certificate = certificate

    async def get(self, url: str, params: Mapping[str, str] = {}) -> HTTPResponse:
        response = await self._request("get", url, params=params)
        return HTTPResponse(response)

    async def post(self, url: str, data: bytes) -> HTTPResponse:
        response = await self._request("post", url, content=data)
        return HTTPResponse(response)

    async def _request(self, method: str, url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        url_parts = urlparse(url)
        assert url_parts.hostname is not None, "Hostname is missing from the url"
        assert url_parts.port is not None, "Port is missing from the url"
        certificate, manager = self._mock_network.get_server(url_parts.hostname, url_parts.port)

        if self._certificate is not None and certificate != self._certificate:
            raise HTTPClientError("Certificate mismatch")

        # Unfortunately there are no unified types for hypercorn and httpx,
        # so we have to cast manually.
        app = cast("httpx._transports.asgi._ASGIApp", manager.app)  # noqa: SLF001
        transport = httpx.ASGITransport(app=app, client=(self._client_host, 9999))
        async with httpx.AsyncClient(transport=transport) as client:
            return await client.request(method, url, *args, **kwargs)
