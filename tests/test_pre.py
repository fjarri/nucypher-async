import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.drivers.peer import Contact, PeerServerWrapper
from nucypher_async.domain import Domain
from nucypher_async.config import UrsulaServerConfig
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.pre import Alice, Bob, encrypt
from nucypher_async.learner import Learner
from nucypher_async.storage import InMemoryStorage
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockPeerClient


@pytest.fixture
async def ursula_servers(mock_network, mock_identity_client, mock_payment_client, ursulas, logger, mock_clock):
    servers = []

    for i in range(10):
        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_set_up(
            staking_provider_address, ursulas[i].operator_address, AmountT.ether(40000))

        config = UrsulaServerConfig(
            domain=Domain.MAINNET,
            contact=Contact('127.0.0.1', 9150 + i),
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=mock_identity_client,
            payment_client=mock_payment_client,
            peer_client=MockPeerClient(mock_network, '127.0.0.1'),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=[],
            clock=mock_clock,
            )

        server = await UrsulaServer.async_init(ursula=ursulas[i], config=config)
        servers.append(server)
        mock_network.add_server(PeerServerWrapper(server))

    # pre-learn about other Ursulas
    for i in range(10):
        nodes = [server._node for server in servers]
        stakes = [AmountT.ether(40000) for server in servers]
        servers[i].learner._add_verified_nodes(nodes, stakes)

    await mock_network.start_all()
    yield servers
    await mock_network.stop_all()


async def test_verified_nodes_iter(nursery, autojump_clock, ursula_servers, mock_network, mock_identity_client, logger):

    peer_client = MockPeerClient(mock_network, '127.0.0.1')
    learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].secure_contact().contact],
        parent_logger=logger)

    addresses = [server._node.staking_provider_address for server in ursula_servers[:3]]
    nodes = []

    with trio.fail_after(10):
        async with learner.verified_nodes_iter(addresses) as aiter:
            async for node in aiter:
                nodes.append(node)

    assert len(nodes) == 3


async def test_granting(nursery, autojump_clock, ursula_servers, mock_network, mock_identity_client,
        mock_payment_client):

    alice = Alice()
    bob = Bob()
    peer_client = MockPeerClient(mock_network, '127.0.0.1')

    alice_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].secure_contact().contact])

    # Fund Alice
    mock_payment_client.mock_set_balance(alice.payment_address, AmountMATIC.ether(1))

    with trio.fail_after(10):
        policy = await alice.grant(
            learner=alice_learner,
            payment_client=mock_payment_client,
            bob=bob.public_info(),
            label=b'some label',
            threshold=2,
            shares=3,
            # TODO: using preselected Ursulas since blockchain is not implemeneted yet
            handpicked_addresses=[server._node.staking_provider_address for server in ursula_servers[:3]])

    message = b'a secret message'
    message_kit = encrypt(policy.encrypting_key, message)

    bob_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[ursula_servers[0].secure_contact().contact])

    with trio.fail_after(10):
        message_back = await bob.retrieve_and_decrypt(bob_learner, message_kit, policy.encrypted_treasure_map,
            remote_alice=alice.public_info())

    assert message_back == message
