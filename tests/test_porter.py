from typing import List, AsyncIterator

import trio
import trio.testing
import pytest

from nucypher_async.domain import Domain
from nucypher_async.server import PorterServerConfig, PorterServer, UrsulaServer
from nucypher_async.mocks import (
    MockNetwork,
    MockIdentityClient,
    MockPaymentClient,
    MockClock,
    MockPeerClient,
    MockHTTPClient,
)
from nucypher_async.utils.logging import Logger
from nucypher_async.utils.ssl import SSLPrivateKey, SSLCertificate
from nucypher_async.storage import InMemoryStorage
from nucypher_async.drivers.peer import Contact, PeerHTTPServer


@pytest.fixture
async def porter_server(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    fully_learned_ursulas: List[UrsulaServer],
    logger: Logger,
    mock_clock: MockClock,
    autojump_clock: trio.testing.MockClock,
) -> AsyncIterator[PorterServer]:

    host = "127.0.0.1"
    port = 9000
    ssl_private_key = SSLPrivateKey.from_seed(b"1231234")
    ssl_certificate = SSLCertificate.self_signed(mock_clock.utcnow(), ssl_private_key, host)

    config = PorterServerConfig(
        domain=Domain.MAINNET,
        host=host,
        port=port,
        ssl_private_key=ssl_private_key,
        ssl_certificate=ssl_certificate,
        identity_client=mock_identity_client,
        peer_client=MockPeerClient(mock_network, host),
        parent_logger=logger,
        storage=InMemoryStorage(),
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
        clock=mock_clock,
    )
    server = PorterServer(config)

    mock_network.add_server(server)

    # TODO: hacky. Add a method to start/stop specific server?
    manager = mock_network.known_servers[(host, port)][1]
    await manager.run(mock_network.nursery)
    yield server
    # TODO: second part of the hack: `fully_learned_ursulas` cleanup stops all the servers,
    # including this one.


async def test_get_ursulas(
    mock_network: MockNetwork,
    # fully_learned_ursulas: List[UrsulaServer],
    porter_server: PorterServer,
    autojump_clock: trio.testing.MockClock,
) -> None:
    mock_client = MockHTTPClient(mock_network, "0.0.0.0", porter_server.ssl_certificate())
    http_client = mock_client.as_httpx_async_client()
    response = await http_client.get("https://127.0.0.1:9000/get_ursulas?quantity=3")
    assert response.status_code == 200
    result = response.json()
    assert len(result["result"]["ursulas"]) == 3
