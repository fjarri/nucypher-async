from functools import partial

from nucypher_async.drivers.rest_client import Contact, SSLContact
from nucypher_async.drivers.rest_server import ServerHandle


class MockRESTClient:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self):
        self._known_servers = {}

    def add_server(self, ursula_server):
        self._known_servers[ursula_server.ssl_contact.contact] = ursula_server

    async def fetch_certificate(self, contact: Contact):
        server = self._known_servers[contact]
        return server.ssl_contact.certificate

    async def ping(self, ssl_contact: SSLContact):
        server = self._known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_ping(ssl_contact.host)

    async def node_metadata_post(self, ssl_contact: SSLContact, metadata_request_bytes):
        server = self._known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_node_metadata_post(metadata_request_bytes)

    async def public_information(self, ssl_contact: SSLContact):
        server = self._known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_public_information()


async def mock_serve_async(nursery, ursula_server, shutdown_trigger):
    ursula_server.start(nursery)
    await shutdown_trigger()
    ursula_server.stop()


def mock_start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(mock_serve_async, nursery, ursula_server, shutdown_trigger=handle._shutdown_trigger()))
    return handle
