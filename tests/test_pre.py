import pytest
import trio

from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_app import make_app
from nucypher_async.ursula import Ursula, UrsulaServer
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
        # TODO: error-prone, make a Learner method
        metadatas = [server.metadata() for server in servers]
        servers[i].learner._verified_nodes = {metadata.node_id: metadata for metadata in metadatas}

    yield servers


async def test_granting(nursery, autojump_clock, ursula_servers, mock_rest_client):

    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    alice = Alice()
    bob = Bob()

    alice_learner = Learner(mock_rest_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])
    for _ in range(50):
        await alice_learner.learning_round()

    policy = await alice.grant(alice_learner, [server.metadata().node_id for server in ursula_servers[:3]],  2, 3)

    bob_learner = Learner(mock_rest_client, seed_contacts=[ursula_servers[0].ssl_contact.contact])
    for _ in range(50):
        await bob_learner.learning_round()

    responses = await bob.retrieve(bob_learner, policy)
    assert len(responses) >= policy.threshold
