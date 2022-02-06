import pytest
import trio

from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_app import make_app
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.pre import Alice, Bob
from nucypher_async.learner import Learner

from .mocks import MockRESTClient, mock_start_in_nursery


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_rest_client():
    yield MockRESTClient()


@pytest.fixture
def ursula_servers(mock_rest_client, ursulas):
    servers = []
    for i in range(10):
        server = UrsulaServer(ursulas[i], port=9150 + i, _rest_client=mock_rest_client)
        servers.append(server)
        mock_rest_client.add_server(server)

    # pre-learn about other Ursulas
    for i in range(10):
        metadatas = [server.metadata() for server in servers]
        servers[i].learner._add_verified_nodes(metadatas)

    yield servers


async def test_granting(nursery, autojump_clock, ursula_servers, mock_rest_client):

    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    alice = Alice()
    bob = Bob()

    alice_learner = Learner(mock_rest_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])

    policy = await alice.grant(
        learner=alice_learner,
        bob=bob,
        label=b'some label',
        threshold=2,
        shares=3,
        # Use preselected Ursulas since blockchain is not implemeneted yet
        handpicked_addresses=[server.ursula.staker_address for server in ursula_servers[:3]])

    """
    message = b'a secret message'
    message_kit = encrypt(policy.encrypting_key, message)

    bob_learner = Learner(mock_rest_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])
    message_back = await bob.retrieve_and_decrypt(bob_learner, message_kit, policy.encrypted_treasure_map)
    assert message_back == message
    """
