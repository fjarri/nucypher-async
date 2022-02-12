import pytest
import trio

from nucypher_async.drivers.eth_account import EthAddress
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_app import make_app
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.pre import Alice, Bob, encrypt
from nucypher_async.learner import Learner

from .mocks import MockRESTClient, MockEthClient, mock_start_in_nursery


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_rest_client():
    yield MockRESTClient()


@pytest.fixture
def mock_eth_client():
    yield MockEthClient()


@pytest.fixture
def ursula_servers(mock_rest_client, mock_eth_client, ursulas):
    servers = []

    for i in range(10):
        staker_address = EthAddress.random()
        server = UrsulaServer(
            ursula=ursulas[i],
            eth_client=mock_eth_client,
            staker_address=staker_address,
            port=9150 + i, _rest_client=mock_rest_client)
        servers.append(server)
        mock_rest_client.add_server(server)
        mock_eth_client.authorize_staker(staker_address)
        mock_eth_client.bond_operator(staker_address, ursulas[i].operator_address)

    # pre-learn about other Ursulas
    for i in range(10):
        metadatas = [server.metadata() for server in servers]
        servers[i].learner._add_verified_nodes(metadatas)

    yield servers


async def test_verified_nodes_iter(nursery, autojump_clock, ursula_servers, mock_rest_client, mock_eth_client, logger):
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]
    learner = Learner(mock_rest_client, mock_eth_client, seed_contacts=[ursula_servers[0].ssl_contact.contact],
        parent_logger=logger)

    addresses = [server.staker_address for server in ursula_servers[:3]]
    nodes = []
    async with learner.verified_nodes_iter(addresses) as aiter:
        async for node in aiter:
            nodes.append(node)

    assert len(nodes) == 3


async def test_granting(nursery, autojump_clock, ursula_servers, mock_rest_client, mock_eth_client):

    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    alice = Alice()
    bob = Bob()

    alice_learner = Learner(mock_rest_client, mock_eth_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])

    policy = await alice.grant(
        learner=alice_learner,
        bob=bob, # TODO: have a "RemoteBob" type for that
        label=b'some label',
        threshold=2,
        shares=3,
        # Use preselected Ursulas since blockchain is not implemeneted yet
        handpicked_addresses=[server.staker_address for server in ursula_servers[:3]])

    message = b'a secret message'
    message_kit = encrypt(policy.encrypting_key, message)

    bob_learner = Learner(mock_rest_client, mock_eth_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])
    message_back = await bob.retrieve_and_decrypt(bob_learner, message_kit, policy.encrypted_treasure_map,
        alice.verifying_key)
    assert message_back == message
