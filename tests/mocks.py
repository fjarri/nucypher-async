from contextlib import asynccontextmanager
from typing import NamedTuple
import weakref

import arrow
import trio
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.drivers.ssl import SSLCertificate
from nucypher_async.drivers.peer import Contact, PeerClient
from nucypher_async.drivers.asgi_app import Request, call_endpoint
from nucypher_async.drivers.asgi_server import ASGIServerHandle
from nucypher_async.pre import HRAC


class MockClock:

    def __init__(self):
        self._start = arrow.utcnow().timestamp() - trio.current_time()

    def utcnow(self):
        return arrow.get(self._start + trio.current_time())


class MockNetwork:

    def __init__(self):
        self.known_servers = {}

    def add_server(self, ursula_server):
        # Breaking the reference loop
        # UrsulaServer ---> MockRestClient ---> MockNetwork -x-> UrsulaServer
        self.known_servers[ursula_server.secure_contact().contact] = weakref.proxy(ursula_server)


class MockPeerClient(PeerClient):
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self, mock_network, host):
        self._mock_network = mock_network
        self._host = host

    async def _resolve_address(self, contact: Contact):
        # TODO: raise ConnectionError if the server is not found
        assert self._mock_network.known_servers[contact]
        return contact

    async def _fetch_certificate(self, contact: Contact):
        server = self._mock_network.known_servers[contact]
        return server.secure_contact().public_key._certificate

    @asynccontextmanager
    async def _http_client(self, certificate: SSLCertificate):
        yield MockHTTPClient(self._mock_network, self._host, certificate)


class MockHTTPClient:

    def __init__(self, mock_network, host, certificate):
        self._mock_network = mock_network
        self._host = host
        self._certificate = certificate
        self._endpoints = {
            ('ping', 'get'): 'endpoint_ping',
            ('node_metadata', 'get'): 'endpoint_node_metadata_get',
            ('node_metadata', 'post'): 'endpoint_node_metadata_post',
            ('public_information', 'get'): 'endpoint_public_information',
            ('reencrypt', 'post'): 'endpoint_reencrypt',
        }

    def _resolve_url(self, url, method):
        proto, _, host_port, endpoint = url.split("/")
        assert proto == "https:"
        host, port = host_port.split(":")
        server = self._mock_network.known_servers[Contact(host, int(port))]
        assert self._certificate == server.secure_contact().public_key._certificate
        return getattr(server, self._endpoints[(endpoint, method)])

    async def get(self, url: str):
        endpoint = self._resolve_url(url, 'get')
        response_bytes, status_code = await call_endpoint(endpoint(Request(self._host, None)))
        return MockResponse(status_code, response_bytes)

    async def post(self, url: str, data: bytes):
        endpoint = self._resolve_url(url, 'post')
        response_bytes, status_code = await call_endpoint(endpoint(Request(self._host, data)))
        return MockResponse(status_code, response_bytes)


class MockResponse:

    def __init__(self, status_code, data: bytes):
        self.status_code = status_code
        self._data = data

    def read(self):
        return self._data

    @property
    def text(self):
        return self._data.decode()


class MockServerHandle(ASGIServerHandle):

    async def __call__(self, *, task_status=trio.TASK_STATUS_IGNORED):
        """
        "Starts" the server without the ASGI app, assuming that REST interface is mocked,
        and server endpoints will be invoked directly.
        """
        async with trio.open_nursery() as nursery:
            await self.server.start(nursery)
            task_status.started()
            await self._shutdown_event.wait()
            self.server.stop()
