from http import HTTPStatus
import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.rest_client import RESTClient, Contact
from nucypher_async.drivers.rest_server import ServerHandle
from nucypher_async.drivers.time import SystemClock
from nucypher_async.storage import InMemoryStorage
from nucypher_async.ursula import Ursula
from nucypher_async.domain import Domain
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
        rest_client=RESTClient(),
        parent_logger=NULL_LOGGER,
        storage=InMemoryStorage(),
        seed_contacts=[],
        clock=SystemClock(),
        )

    return UrsulaServer(ursula=Ursula(), config=config, staking_provider_address=IdentityAddress(os.urandom(20)))


async def test_client_real_server(nursery, capsys, ursula_server):
    handle = ServerHandle(ursula_server)
    await nursery.start(handle)

    client = RESTClient()
    response = await client.ping(ursula_server.ssl_contact())
    assert response == '127.0.0.1'

    handle.shutdown()
    capsys.readouterr()
