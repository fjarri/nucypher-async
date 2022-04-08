import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.pre import Alice, Bob, encrypt
from nucypher_async.learner import Learner
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient

from .mocks import MockNetwork, MockRESTClient, mock_start_in_nursery


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_network():
    yield MockNetwork()


@pytest.fixture
def mock_identity_client():
    yield MockIdentityClient()


@pytest.fixture
def mock_payment_client():
    yield MockPaymentClient()


@pytest.fixture
async def ursula_servers(mock_network, mock_identity_client, mock_payment_client, ursulas, logger):
    servers = []

    for i in range(10):
        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_approve(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_stake(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_bond_operator(staking_provider_address, ursulas[i].operator_address)
        # TODO: UrsulaServer should do it on startup
        mock_identity_client.mock_confirm_operator(ursulas[i].operator_address)

        server = await UrsulaServer.async_init(
            ursula=ursulas[i],
            identity_client=mock_identity_client,
            payment_client=mock_payment_client,
            parent_logger=logger,
            host='127.0.0.1',
            port=9150 + i,
            _rest_client=MockRESTClient(mock_network, '127.0.0.1'))
        servers.append(server)
        mock_network.add_server(server)

    # pre-learn about other Ursulas
    for i in range(10):
        metadatas = [server.metadata() for server in servers]
        stakes = [AmountT.ether(40000) for server in servers]
        servers[i].learner._add_verified_nodes(metadatas, stakes)

    yield servers


async def test_verified_nodes_iter(nursery, autojump_clock, ursula_servers, mock_network, mock_identity_client, logger):
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]
    rest_client = MockRESTClient(mock_network, '127.0.0.1')
    learner = Learner(
        rest_client=rest_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].ssl_contact().contact],
        parent_logger=logger)

    addresses = [server.staking_provider_address for server in ursula_servers[:3]]
    nodes = []
    async with learner.verified_nodes_iter(addresses) as aiter:
        async for node in aiter:
            nodes.append(node)

    assert len(nodes) == 3


async def test_granting(nursery, autojump_clock, ursula_servers, mock_network, mock_identity_client,
        mock_payment_client):

    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    alice = Alice()
    bob = Bob()
    rest_client = MockRESTClient(mock_network, '127.0.0.1')

    alice_learner = Learner(
        rest_client=rest_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].ssl_contact().contact])

    # Fund Alice
    mock_payment_client.mock_set_balance(alice.payment_address, AmountMATIC.ether(1))

    policy = await alice.grant(
        learner=alice_learner,
        payment_client=mock_payment_client,
        bob=bob.public_info(),
        label=b'some label',
        threshold=2,
        shares=3,
        # TODO: using preselected Ursulas since blockchain is not implemeneted yet
        handpicked_addresses=[server.staking_provider_address for server in ursula_servers[:3]])

    message = b'a secret message'
    message_kit = encrypt(policy.encrypting_key, message)

    bob_learner = Learner(
        rest_client=rest_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].ssl_contact().contact])
    message_back = await bob.retrieve_and_decrypt(bob_learner, message_kit, policy.encrypted_treasure_map,
        remote_alice=alice.public_info())
    assert message_back == message
