from contextlib import asynccontextmanager
from typing import NamedTuple
from urllib.parse import urlparse
import weakref

import arrow
import trio

from ..utils.ssl import SSLCertificate
from ..drivers.peer import Contact, PeerClient
from .asgi import MockHTTPClient


class MockPeerClient(PeerClient):
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self, mock_network, host):
        self._mock_network = mock_network
        self._host = host

    async def _resolve_address(self, contact: Contact):
        # TODO: raise ConnectionError if the server is not found
        assert self._mock_network.known_servers[(contact.host, contact.port)]
        return contact

    async def _fetch_certificate(self, contact: Contact):
        certificate, _server = self._mock_network.known_servers[(contact.host, contact.port)]
        return certificate

    @asynccontextmanager
    async def _http_client(self, certificate: SSLCertificate):
        yield MockHTTPClient(self._mock_network, self._host, certificate)
