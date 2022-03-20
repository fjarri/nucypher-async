from http import HTTPStatus
import os

import pytest
import trio

from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import async_client_ssl
from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient


async def test_client_real_server(nursery, capsys):
    identity_client = MockIdentityClient()
    payment_client = MockPaymentClient()
    server = UrsulaServer(ursula=Ursula(), identity_client=identity_client,
        payment_client=payment_client, staking_provider_address=IdentityAddress(os.urandom(20)))
    handle = start_in_nursery(nursery, server)

    # TODO: have some event in the server that could be waited for to ensure finished startup?
    await trio.sleep(1)

    async with async_client_ssl(server.ssl_contact.certificate) as client:
        response = await client.get(f'{server.ssl_contact.url}/ping')
        assert response.status_code == HTTPStatus.OK
        assert response.text == '127.0.0.1'

    handle.shutdown()
    capsys.readouterr()
