import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
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
def ursula_servers(mock_network, mock_identity_client, ursulas, logger):
    servers = []
    payment_client = MockPaymentClient()

    for i in range(10):

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        staking_provider_address = IdentityAddress(os.urandom(20))

        server = UrsulaServer(
            ursula=ursulas[i],
            identity_client=mock_identity_client,
            payment_client=payment_client,
            staking_provider_address=staking_provider_address,
            port=9150 + i,
            seed_contacts=seed_contacts,
            parent_logger=logger,
            _rest_client=MockRESTClient(mock_network, '127.0.0.1'))

        servers.append(server)
        mock_network.add_server(server)

        mock_identity_client.mock_approve(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_stake(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_bond_operator(staking_provider_address, ursulas[i].operator_address)
        # TODO: UrsulaServer should do it on startup
        mock_identity_client.mock_confirm_operator(ursulas[i].operator_address)

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
