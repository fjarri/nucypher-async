from functools import partial
import weakref

from nucypher_async.drivers.eth_client import Address
from nucypher_async.drivers.rest_client import Contact, SSLContact
from nucypher_async.drivers.rest_server import ServerHandle


class MockNetwork:

    def __init__(self):
        self.known_servers = {}

    def add_server(self, ursula_server):
        # Breaking the reference loop
        # UrsulaServer ---> MockRestClient ---> MockNetwork -x-> UrsulaServer
        self.known_servers[ursula_server.ssl_contact.contact] = weakref.proxy(ursula_server)


class MockRESTClient:
    """
    A counterpart of NetworkMiddleware with raw data/response pass-through directly to the server.
    """

    def __init__(self, mock_network, host):
        self._mock_network = mock_network
        self._remote_addr = host

    async def fetch_certificate(self, contact: Contact):
        server = self._mock_network.known_servers[contact]
        return server.ssl_contact.certificate

    async def ping(self, ssl_contact: SSLContact):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        # TODO: actually we need to pass the caller's host here, not the target's host.
        # How do we do that? In production, the host is a global state,
        # if we start passing it explicitly to the client, it'll look weird.
        return await server.endpoint_ping(self._remote_addr)

    async def node_metadata_post(self, ssl_contact: SSLContact, metadata_request_bytes):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_node_metadata_post(metadata_request_bytes)

    async def public_information(self, ssl_contact: SSLContact):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_public_information()

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request_bytes):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_reencrypt(reencryption_request_bytes)


class MockEthClient:

    def __init__(self):
        self.staker_to_operator = {}
        self.operator_to_staker = {}
        self.operator_confirmed = set()
        self.eth_balances = {}
        self.staker_authorization = set()

    def authorize_staker(self, staker_address: Address):
        self.staker_authorization.add(staker_address)

    def bond_operator(self, staker_address: Address, operator_address: Address):
        self.staker_to_operator[staker_address] = operator_address
        self.operator_to_staker[operator_address] = staker_address

    def confirm_operator_address(self, operator_address: Address):
        if operator_address not in self.operator_to_staker:
            raise RuntimeError("No stake associated with the operator")
        staker_address = self.operator_to_staker[operator_address]
        if operator_address in self.operator_confirmed:
            raise RuntimeError("Operator address is already confirmed")
        self.operator_confirmed.add(operator_address)

    async def get_staker_address(self, operator_address: Address):
        if operator_address not in self.operator_to_staker:
            raise RuntimeError("Operator is not bonded")
        return self.operator_to_staker[operator_address]

    async def get_operator_address(self, staker_address: Address):
        if staker_address not in self.staker_to_operator:
            raise RuntimeError("Operator is not bonded")
        return self.staker_to_operator[staker_address]

    async def is_staker_authorized(self, staker_address: Address):
        return staker_address in self.staker_authorization

    async def is_operator_confirmed(self, operator_address: Address):
        return operator_address in self.operator_confirmed

    async def get_eth_balance(self, address: Address):
        return self.eth_balances.get(address, 0)


async def mock_serve_async(nursery, ursula_server, shutdown_trigger):
    ursula_server.start(nursery)
    await shutdown_trigger()
    ursula_server.stop()


def mock_start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(mock_serve_async, nursery, ursula_server, shutdown_trigger=handle._shutdown_trigger()))
    return handle
