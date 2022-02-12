import pytest
import trio

from nucypher_async.drivers.eth_account import EthAddress
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
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

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        staker_address = EthAddress.random()

        server = UrsulaServer(
            ursula=ursulas[i],
            eth_client=mock_eth_client,
            staker_address=staker_address,
            port=9150 + i,
            seed_contacts=seed_contacts,
            _rest_client=mock_rest_client)

        servers.append(server)
        mock_rest_client.add_server(server)
        mock_eth_client.authorize_staker(staker_address)
        mock_eth_client.bond_operator(staker_address, ursulas[i].operator_address)

    yield servers


async def test_learning(nursery, autojump_clock, ursula_servers):

    # Create 10 Ursulas
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    while True:
        # Wait multiple learning cycles
        await trio.sleep(100)

        known_nodes = {
            handle.ursula_server.staker_address: set(handle.ursula_server.learner._verified_nodes)
            for handle in handles}

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 9 for nodes in known_nodes.values()):
            break
