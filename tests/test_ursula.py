import pytest
import trio

from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_app import make_app
from nucypher_async.drivers.rest_client import Contact
from nucypher_async.ursula import Ursula, UrsulaServer
from nucypher_async.learner import Learner

from .mocks import MockRESTClient, mock_start_in_nursery


async def test_client_with_background_tasks():
    server = UrsulaServer(Ursula())
    app = make_app(server)

    async with app.test_app() as test_app:

        test_client = test_app.test_client()
        assert server.started

        r = await test_client.get('/ping')
        assert r.status_code == 200

        await test_app.shutdown()

    assert not server.started


async def test_client_no_background_tasks():
    server = UrsulaServer(Ursula())
    app = make_app(server)

    test_client = app.test_client()

    assert not server.started
    response = await test_client.get('/ping')
    assert response.status_code == 200


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

        # Each Ursula knows only about one other Ursula,
        # but the graph is fully connected.
        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        server = UrsulaServer(ursulas[i], port=9150 + i, seed_contacts=seed_contacts, _rest_client=mock_rest_client)

        servers.append(server)
        mock_rest_client.add_server(server)

    yield servers


async def test_learning(nursery, autojump_clock, ursula_servers):

    # Create 10 Ursulas
    handles = [mock_start_in_nursery(nursery, server) for server in ursula_servers]

    while True:
        # Wait multiple learning cycles
        await trio.sleep(100)

        known_nodes = {
            handle.ursula_server.ursula.id: set(handle.ursula_server.learner._verified_nodes)
            for handle in handles}

        # Each Ursula should know about every other Ursula by now.
        if all(len(nodes) == 9 for nodes in known_nodes.values()):
            break
