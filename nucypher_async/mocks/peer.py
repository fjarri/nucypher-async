from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from ..drivers.peer import Contact, PeerClient, PeerPublicKey
from ..utils.ssl import SSLCertificate
from .asgi import MockHTTPClient, MockNetwork


class MockPeerClient(PeerClient):
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through
    directly to the server.
    """

    def __init__(self, mock_network: MockNetwork, host: str):
        self._mock_network = mock_network
        self._host = host

    async def _fetch_certificate(self, contact: Contact) -> SSLCertificate:
        # TODO: raise ConnectionError if the server is not found
        certificate, _manager = self._mock_network.get_server(contact.host, contact.port)
        return certificate

    @asynccontextmanager
    async def _http_client(self, public_key: PeerPublicKey) -> AsyncIterator[httpx.AsyncClient]:
        client = MockHTTPClient(self._mock_network, self._host, public_key._as_ssl_certificate())  # noqa: SLF001
        yield client.as_httpx_async_client()
