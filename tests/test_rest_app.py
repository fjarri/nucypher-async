from http import HTTPStatus

import pytest
import trio

from nucypher_async.drivers.rest_app import make_app
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer


async def test_client_with_background_tasks():
    server = UrsulaServer(Ursula())
    app = make_app(server)

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
    server = UrsulaServer(Ursula())
    app = make_app(server)

    test_client = app.test_client()

    assert not server.started
    response = await test_client.get('/ping')
    assert response.status_code == 200
    # For some reason
    assert await response.data == b'<local>'
