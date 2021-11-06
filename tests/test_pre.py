import pytest
import trio

from nucypher_async.server import start_in_nursery, mock_start_in_nursery
from nucypher_async.ursula import Ursula, UrsulaServer
from nucypher_async.app import make_app
from nucypher_async.middleware import MockMiddleware
from nucypher_async.pre import Alice, Bob
from nucypher_async.learner import Learner


@pytest.fixture
def ursulas():
    yield [Ursula(i) for i in range(10)]


@pytest.fixture
def mock_middleware():
    yield MockMiddleware()


@pytest.fixture
def ursula_servers(mock_middleware, ursulas):
    servers = []
    for i in range(10):
        server = UrsulaServer(ursulas[i], port=9150 + i, middleware=mock_middleware)
        servers.append(server)
        mock_middleware.add_server(server.address, server)

    # pre-learn about other Ursulas
    for i in range(10):
        # TODO: error-prone, make a Learner method
        metadatas = [server.ursula.metadata(server.address) for server in servers]
        servers[i].learner.nodes = {metadata.id: metadata for metadata in metadatas}

    yield servers


async def test_granting(nursery, autojump_clock, ursula_servers, mock_middleware):

    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    alice = Alice()
    bob = Bob()

    alice_learner = Learner(mock_middleware, seed_addresses=[ursula_servers[0].address])
    alice_learner.start(nursery)
    await trio.sleep(100)

    policy = await alice.grant(alice_learner, 2, 3)

    bob_learner = Learner(mock_middleware, seed_addresses=[ursula_servers[0].address])
    bob_learner.start(nursery)
    await trio.sleep(100)
    responses = await bob.retrieve(bob_learner, policy)
    assert len(responses) >= policy.threshold
