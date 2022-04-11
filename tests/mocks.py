from functools import partial
from typing import NamedTuple
import weakref

import arrow
import trio
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.drivers.rest_client import Contact, SSLContact
from nucypher_async.drivers.rest_server import ServerHandle
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
        self.known_servers[ursula_server.ssl_contact().contact] = weakref.proxy(ursula_server)


class MockRESTClient:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self, mock_network, host):
        self._mock_network = mock_network
        self._remote_addr = host

    async def fetch_certificate(self, contact: Contact):
        server = self._mock_network.known_servers[contact]
        return server.ssl_contact().certificate

    async def ping(self, ssl_contact: SSLContact):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact().certificate
        # TODO: actually we need to pass the caller's host here, not the target's host.
        # How do we do that? In production, the host is a global state,
        # if we start passing it explicitly to the client, it'll look weird.
        return await server.endpoint_ping(self._remote_addr)

    async def node_metadata_post(self, ssl_contact: SSLContact, metadata_request_bytes):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact().certificate
        return await server.endpoint_node_metadata_post(self._remote_addr, metadata_request_bytes)

    async def public_information(self, ssl_contact: SSLContact):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact().certificate
        return await server.endpoint_public_information()

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request_bytes):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact().certificate
        return await server.endpoint_reencrypt(reencryption_request_bytes)


class MockServerHandle(ServerHandle):

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
