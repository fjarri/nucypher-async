from http import HTTPStatus
import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.rest_app import make_ursula_app
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient


async def test_client_with_background_tasks():
    identity_client = MockIdentityClient()
    payment_client = MockPaymentClient()
    server = UrsulaServer(ursula=Ursula(), identity_client=identity_client,
        payment_client=payment_client, staking_provider_address=IdentityAddress(os.urandom(20)))
    app = make_ursula_app(server)

    async with app.test_app() as test_app:

        test_client = test_app.test_client()
        assert server.started

        r = await test_client.get('/ping')
        assert r.status_code == HTTPStatus.OK

        # For whatever reason the test app response returns bytes instead of text
        assert await r.data == b'<local>'

        await test_app.shutdown()

    assert not server.started


async def test_client_no_background_tasks():
    identity_client = MockIdentityClient()
    payment_client = MockPaymentClient()
    server = UrsulaServer(ursula=Ursula(), identity_client=identity_client,
        payment_client=payment_client, staking_provider_address=IdentityAddress(os.urandom(20)))
    app = make_ursula_app(server)

    test_client = app.test_client()

    assert not server.started
    response = await test_client.get('/ping')
    assert response.status_code == 200
    # For some reason
    assert await response.data == b'<local>'
