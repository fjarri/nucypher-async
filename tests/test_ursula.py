import pytest
import trio

from nucypher_async.server import start_in_nursery, mock_start_in_nursery
from nucypher_async.ursula import Ursula, UrsulaServer, Learner
from nucypher_async.app import make_app
from nucypher_async.middleware import MockMiddleware
from nucypher_async.alice import Alice
from nucypher_async.bob import Bob


async def test_client_with_background_tasks():
    server = UrsulaServer(Ursula(0))
    app = make_app(server)

    async with app.test_app() as test_app:

        test_client = test_app.test_client()
        assert server.started

        r = await test_client.get('/ping')
        assert r.status_code == 200

        await test_app.shutdown()

    assert not server.started


async def test_client_no_background_tasks():
    server = UrsulaServer(Ursula(0))
    app = make_app(server)

    test_client = app.test_client()

    assert not server.started
    response = await test_client.get('/ping')
    assert response.status_code == 200


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

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_addresses = [f'localhost:{9150+i-1}']
        else:
            seed_addresses = []

        server = UrsulaServer(ursulas[i], port=9150 + i, seed_addresses=seed_addresses, middleware=mock_middleware)

        servers.append(server)
        mock_middleware.add_server(server.address, server)

    yield servers


async def test_learning(nursery, autojump_clock, ursula_servers):

    # Create 10 Ursulas
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    while True:
        # Wait multiple learning cycles
        await trio.sleep(100)

        known_nodes = {
            handle.ursula_server.ursula.id: set(handle.ursula_server.learner.nodes)
            for handle in handles}

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 9 for nodes in known_nodes.values()):
            break


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
