import os

import pytest
import trio

from nucypher_async.drivers.eth_client import Address
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.learner import Learner

from .mocks import MockNetwork, MockRESTClient, MockEthClient, mock_start_in_nursery


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_network():
    yield MockNetwork()


@pytest.fixture
def mock_eth_client():
    yield MockEthClient()


@pytest.fixture
def ursula_servers(mock_network, mock_eth_client, ursulas, logger):
    servers = []
    for i in range(10):

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        staking_provider_address = Address(os.urandom(20))

        server = UrsulaServer(
            ursula=ursulas[i],
            eth_client=mock_eth_client,
            staking_provider_address=staking_provider_address,
            port=9150 + i,
            seed_contacts=seed_contacts,
            parent_logger=logger,
            _rest_client=MockRESTClient(mock_network, '127.0.0.1'))

        servers.append(server)
        mock_network.add_server(server)
        mock_eth_client.authorize_staking_provider(staking_provider_address)
        mock_eth_client.bond_operator(staking_provider_address, ursulas[i].operator_address)
        mock_eth_client.confirm_operator_address(ursulas[i].operator_address)

    yield servers


async def test_learning(nursery, autojump_clock, ursula_servers):

    # Create 10 Ursulas
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    while True:
        # Wait multiple learning cycles
        await trio.sleep(100)

        known_nodes = {
            handle.ursula_server.staking_provider_address: set(handle.ursula_server.learner.fleet_sensor._verified_nodes)
            for handle in handles}

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 9 for nodes in known_nodes.values()):
            break
