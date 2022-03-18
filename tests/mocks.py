from functools import partial
from typing import NamedTuple
import weakref

import trio
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.drivers.rest_client import Contact, SSLContact
from nucypher_async.drivers.rest_server import ServerHandle
from nucypher_async.pre import HRAC


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
        return await server.endpoint_node_metadata_post(self._remote_addr, metadata_request_bytes)

    async def public_information(self, ssl_contact: SSLContact):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_public_information()

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request_bytes):
        server = self._mock_network.known_servers[ssl_contact.contact]
        assert ssl_contact.certificate == server.ssl_contact.certificate
        return await server.endpoint_reencrypt(reencryption_request_bytes)


class MockIdentityClient:

    def __init__(self):
        self.staking_provider_to_operator = {}
        self.operator_to_staking_provider = {}
        self.operator_confirmed = set()
        self.balances = {}
        self.staking_provider_authorization = set()

    def authorize_staking_provider(self, staking_provider_address: IdentityAddress):
        self.staking_provider_authorization.add(staking_provider_address)

    def bond_operator(self, staking_provider_address: IdentityAddress, operator_address: IdentityAddress):
        self.staking_provider_to_operator[staking_provider_address] = operator_address
        self.operator_to_staking_provider[operator_address] = staking_provider_address

    def confirm_operator_address(self, operator_address: IdentityAddress):
        if operator_address not in self.operator_to_staking_provider:
            raise RuntimeError("No stake associated with the operator")
        staking_provider_address = self.operator_to_staking_provider[operator_address]
        if operator_address in self.operator_confirmed:
            raise RuntimeError("Operator address is already confirmed")
        self.operator_confirmed.add(operator_address)

    async def get_staking_provider_address(self, operator_address: IdentityAddress):
        if operator_address not in self.operator_to_staking_provider:
            raise RuntimeError("Operator is not bonded")
        return self.operator_to_staking_provider[operator_address]

    async def get_operator_address(self, staking_provider_address: IdentityAddress):
        if staking_provider_address not in self.staking_provider_to_operator:
            raise RuntimeError("Operator is not bonded")
        return self.staking_provider_to_operator[staking_provider_address]

    async def is_staking_provider_authorized(self, staking_provider_address: IdentityAddress):
        return staking_provider_address in self.staking_provider_authorization

    async def is_operator_confirmed(self, operator_address: IdentityAddress):
        return operator_address in self.operator_confirmed

    async def get_balance(self, address: IdentityAddress):
        return self.balances.get(address, 0)


class Policy(NamedTuple):
    policy_id: HRAC
    start: int
    end: int
    shares: int


class MockPaymentNetwork:

    def __init__(self):
        self.policies = {}
        self.balances = {}
        self.fee = AmountMATIC.gwei(1)

    def set_balance(self, address, value):
        self.balances[address] = value

    def pay(self, address, value):
        assert address in self.balances
        assert self.balances[address] >= value
        self.balances[address] -= value


class MockPaymentClient:

    def __init__(self, network):
        self._network = network

    async def is_policy_active(self, hrac):
        if hrac not in self._network.policies:
            return False

        now = int(trio.current_time())
        if now > self._network.policies[hrac].end:
            return False

        return True

    async def get_policy_cost(self, shares, start, end):
        return self._network.fee * (end - start) * shares

    def with_signer(self, signer):
        return MockSigningPaymentClient(self._network, signer)


class MockSigningPaymentClient(MockPaymentClient):

    def __init__(self, network, signer):
        super().__init__(network)
        self._signer = signer

    async def create_policy(self, hrac: HRAC, shares: int, policy_start: int, policy_end: int):
        assert hrac not in self._network.policies

        cost = await self.get_policy_cost(shares, policy_start, policy_end)
        self._network.pay(self._signer.address, cost)
        self._network.policies[hrac] = Policy(
            policy_id=hrac, start=policy_start, end=policy_end, shares=shares)


async def mock_serve_async(nursery, ursula_server, shutdown_trigger):
    ursula_server.start(nursery)
    await shutdown_trigger()
    ursula_server.stop()


def mock_start_in_nursery(nursery, ursula_server):
    handle = ServerHandle(ursula_server)
    nursery.start_soon(partial(mock_serve_async, nursery, ursula_server, shutdown_trigger=handle._shutdown_trigger()))
    return handle
