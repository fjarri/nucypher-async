from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import trio

from ..node import NodeServer
from ..node.handle import NodeServerAsHTTPServer
from ..node_base import Contact, PeerClient, PeerPublicKey
from ..utils.ssl import SSLCertificate
from .asgi import MockHTTPClient, MockHTTPNetwork, MockHTTPServerHandle


class MockPeerClient(PeerClient):
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through
    directly to the server.
    """

    # TODO: technically, a peer client doesn't need to have its own contact.
    # This only comes into play if it's a client run by a node,
    # and the node sends info about itself,
    # so the receiver can check that the host of the contact it received matches
    # the host of the sender (otherwise it can be a DDoS attack).
    def __init__(self, network: "MockP2PNetwork", contact: Contact | None = None):
        self._network = network
        self._contact = contact
        self._client = MockHTTPClient(
            network._mock_http_network,  # noqa: SLF001
            contact.host if contact else "mock_hostname",
        )

    async def _fetch_certificate(self, contact: Contact) -> SSLCertificate:
        # TODO: raise ConnectionError if the server is not found
        public_key = self._network.get_public_key(contact)
        return public_key._as_ssl_certificate()  # noqa: SLF001

    @asynccontextmanager
    async def _http_client(self, _public_key: PeerPublicKey) -> AsyncIterator[httpx.AsyncClient]:
        # TODO: use the `public_key` argument
        yield self._client.as_httpx_async_client()


class MockNodeServerHandle:
    def __init__(self, handle: MockHTTPServerHandle):
        self._handle = handle

    async def startup(self) -> None:
        await self._handle.startup()

    async def shutdown(self) -> None:
        await self._handle.shutdown()


class MockP2PNetwork:
    def __init__(self, nursery: trio.Nursery):
        self._mock_http_network = MockHTTPNetwork(nursery)

    def add_server(self, server: NodeServer) -> MockNodeServerHandle:
        handle = self._mock_http_network.add_server(NodeServerAsHTTPServer(server))
        return MockNodeServerHandle(handle)

    async def startup(self, contact: Contact) -> None:
        await self._mock_http_network.startup(contact.host, contact.port)

    async def shutdown(self, contact: Contact) -> None:
        await self._mock_http_network.shutdown(contact.host, contact.port)

    def get_public_key(self, contact: Contact) -> PeerPublicKey:
        certificate, _manager = self._mock_http_network.get_server(contact.host, contact.port)
        return PeerPublicKey(certificate)
