from http import HTTPStatus
import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.asgi_app import make_ursula_app
from nucypher_async.drivers.peer import PeerClient, Contact
from nucypher_async.drivers.time import SystemClock
from nucypher_async.domain import Domain
from nucypher_async.storage import InMemoryStorage
from nucypher_async.ursula import Ursula
from nucypher_async.config import UrsulaServerConfig
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient
from nucypher_async.utils.logging import NULL_LOGGER


@pytest.fixture
def ursula_server():
    config = UrsulaServerConfig(
        domain=Domain.MAINNET,
        contact=Contact('127.0.0.1', 9151),
        identity_client=MockIdentityClient(),
        payment_client=MockPaymentClient(),
        peer_client=PeerClient(),
        parent_logger=NULL_LOGGER,
        storage=InMemoryStorage(),
        seed_contacts=[],
        clock=SystemClock(),
        )

    return UrsulaServer(ursula=Ursula(), config=config, staking_provider_address=IdentityAddress(os.urandom(20)))


async def test_client_with_background_tasks(ursula_server):

    ursula_app = make_ursula_app(ursula_server)

    async with ursula_app.test_app() as test_app:

        test_client = test_app.test_client()
        assert ursula_server.started

        r = await test_client.get('/ping')
        assert r.status_code == HTTPStatus.OK

        # For whatever reason the test app response returns bytes instead of text
        assert await r.data == b'<local>'

        await test_app.shutdown()

    assert not ursula_server.started


async def test_client_no_background_tasks(ursula_server):

    ursula_app = make_ursula_app(ursula_server)

    test_client = ursula_app.test_client()

    assert not ursula_server.started
    response = await test_client.get('/ping')
    assert response.status_code == 200
    # For some reason
    assert await response.data == b'<local>'
