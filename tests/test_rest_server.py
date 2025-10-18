import os

import pytest
import trio

from nucypher_async.characters.pre import Ursula
from nucypher_async.domain import Domain
from nucypher_async.drivers.http_server import HTTPServerHandle
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.peer import Contact, PeerClient, UrsulaHTTPServer
from nucypher_async.drivers.time import SystemClock
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient
from nucypher_async.p2p.ursula import UrsulaClient
from nucypher_async.server import UrsulaServer, UrsulaServerConfig
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils.logging import NULL_LOGGER


@pytest.fixture
def ursula_server() -> UrsulaServer:
    config = UrsulaServerConfig(
        domain=Domain.MAINNET,
        contact=Contact("127.0.0.1", 9151),
        identity_client=MockIdentityClient(),
        payment_client=MockPaymentClient(),
        peer_client=PeerClient(),
        parent_logger=NULL_LOGGER,
        storage=InMemoryStorage(),
        seed_contacts=[],
        clock=SystemClock(),
    )

    return UrsulaServer(
        ursula=Ursula(),
        config=config,
        staking_provider_address=IdentityAddress(os.urandom(20)),
    )


async def test_client_real_server(
    nursery: trio.Nursery,
    capsys: pytest.CaptureFixture[str],
    ursula_server: UrsulaServer,
) -> None:
    handle = HTTPServerHandle(UrsulaHTTPServer(ursula_server))
    await nursery.start(handle.startup)

    client = UrsulaClient(PeerClient())
    response = await client.ping(ursula_server.secure_contact())
    assert response == "127.0.0.1"

    response = await client.status(ursula_server.secure_contact())

    await handle.shutdown()
    capsys.readouterr()
