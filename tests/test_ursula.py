import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.config import UrsulaServerConfig
from nucypher_async.domain import Domain
from nucypher_async.storage import InMemoryStorage
from nucypher_async.learner import Learner
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient

from .mocks import MockNetwork, MockRESTClient, mock_start_in_nursery


@pytest.fixture
async def ursula_servers(mock_network, mock_identity_client, mock_payment_client, mock_clock, ursulas, logger):
    servers = []
    for i in range(10):

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_approve(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_stake(staking_provider_address, AmountT.ether(40000))
        mock_identity_client.mock_bond_operator(staking_provider_address, ursulas[i].operator_address)
        # TODO: UrsulaServer should do it on startup
        mock_identity_client.mock_confirm_operator(ursulas[i].operator_address)

        config = UrsulaServerConfig(
            domain=Domain.MAINNET,
            contact=Contact('127.0.0.1', 9150 + i),
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=mock_identity_client,
            payment_client=mock_payment_client,
            rest_client=MockRESTClient(mock_network, '127.0.0.1'),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=seed_contacts,
            clock=mock_clock,
            )

        server = await UrsulaServer.async_init(ursula=ursulas[i], config=config)
        servers.append(server)
        mock_network.add_server(server)

    yield servers


async def test_learning(nursery, autojump_clock, ursula_servers):

    # Create 10 Ursulas
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    while True:
        # Wait multiple learning cycles
        # TODO: find a way to wait until the learning is done, and measure how much time has passed
        await trio.sleep(100)

        known_nodes = {
            handle.server.staking_provider_address: handle.server.learner.metadata_to_announce()
            for handle in handles}

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 10 for nodes in known_nodes.values()):
            break
