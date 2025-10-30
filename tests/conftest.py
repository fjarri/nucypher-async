import itertools
import os
from collections.abc import AsyncIterator
from ipaddress import IPv4Address

import pytest
import trio

from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.domain import Domain
from nucypher_async.drivers.identity import AmountT, IdentityAddress
from nucypher_async.drivers.peer import Contact
from nucypher_async.mocks import (
    MockCBDClient,
    MockClock,
    MockHTTPServerHandle,
    MockIdentityClient,
    MockNetwork,
    MockPeerClient,
    MockPREClient,
)
from nucypher_async.server import (
    NodeServer,
    NodeServerConfig,
    PeerServerConfig,
    PorterServer,
    PorterServerConfig,
)
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils import logging
from nucypher_async.utils.ssl import SSLCertificate, SSLPrivateKey


@pytest.fixture(scope="session")
def logger() -> logging.Logger:
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(level=logging.DEBUG, handlers=[logging.ConsoleHandler(stderr_at=None)])


@pytest.fixture
async def mock_clock() -> MockClock:
    return MockClock()


@pytest.fixture
def reencryptors() -> list[Reencryptor]:
    return [Reencryptor() for i in range(10)]


@pytest.fixture
def decryptors() -> list[Decryptor]:
    return [Decryptor() for i in range(10)]


@pytest.fixture
def mock_network(nursery: trio.Nursery) -> MockNetwork:
    return MockNetwork(nursery)


@pytest.fixture
def mock_identity_client() -> MockIdentityClient:
    return MockIdentityClient()


@pytest.fixture
def mock_pre_client() -> MockPREClient:
    return MockPREClient()


@pytest.fixture
def mock_cbd_client() -> MockCBDClient:
    return MockCBDClient()


@pytest.fixture
async def lonely_nodes(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    mock_cbd_client: MockCBDClient,
    reencryptors: list[Reencryptor],
    decryptors: list[Decryptor],
    logger: logging.Logger,
    mock_clock: MockClock,
) -> list[tuple[MockHTTPServerHandle, NodeServer]]:
    servers = []

    for i in range(10):
        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_set_up(
            staking_provider_address, reencryptors[i].operator_address, AmountT.ether(40000)
        )

        peer_server_config = PeerServerConfig(
            bind_to=IPv4Address("127.0.0.1"),
            contact=Contact("127.0.0.1", 9150 + i),
            ssl_certificate=None,
            ssl_private_key=None,
            ssl_ca_chain=None,
        )

        config = NodeServerConfig(
            domain=Domain.MAINNET,
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=mock_identity_client,
            pre_client=mock_pre_client,
            cbd_client=mock_cbd_client,
            peer_client=MockPeerClient(mock_network, "127.0.0.1"),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=[],
            clock=mock_clock,
        )

        server = await NodeServer.async_init(
            reencryptor=reencryptors[i],
            decryptor=decryptors[i],
            peer_server_config=peer_server_config,
            config=config,
        )
        handle = mock_network.add_server(server)
        servers.append((handle, server))

    return servers


@pytest.fixture
async def chain_seeded_nodes(
    lonely_nodes: list[tuple[MockHTTPServerHandle, NodeServer]],
) -> AsyncIterator[list[NodeServer]]:
    # Each node knows only about one other node,
    # but the graph is fully connected.
    for (_handle1, server1), (_handle2, server2) in itertools.pairwise(lonely_nodes):
        server2.learner._test_set_seed_contacts([server1.secure_contact().contact])

    for handle, _server in lonely_nodes:
        await handle.startup()

    yield [server for _handle, server in lonely_nodes]

    for handle, _server in lonely_nodes:
        await handle.shutdown()


@pytest.fixture
async def fully_learned_nodes(
    mock_identity_client: MockIdentityClient,
    lonely_nodes: list[tuple[MockHTTPServerHandle, NodeServer]],
) -> AsyncIterator[list[NodeServer]]:
    # Each node knows only about one other node,
    # but the graph is fully connected.
    for _handle, server in lonely_nodes:
        for _other_handle, other_server in lonely_nodes:
            if other_server is server:
                continue

            peer_info = other_server._node  # TODO: add a proper method to NodeServer
            async with mock_identity_client.session() as session:
                stake = await session.get_staked_amount(peer_info.staking_provider_address)
            server.learner._test_add_verified_node(peer_info, stake)

    for handle, _server in lonely_nodes:
        await handle.startup()

    yield [server for _handle, server in lonely_nodes]

    for handle, _server in lonely_nodes:
        await handle.shutdown()


@pytest.fixture
async def porter_server(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    fully_learned_nodes: list[NodeServer],
    logger: logging.Logger,
    mock_clock: MockClock,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> AsyncIterator[PorterServer]:
    host = "127.0.0.1"
    port = 9000
    ssl_private_key = SSLPrivateKey.from_seed(b"1231234")
    ssl_certificate = SSLCertificate.self_signed(mock_clock.utcnow(), ssl_private_key, host)

    peer_server_config = PeerServerConfig(
        bind_to=IPv4Address("127.0.0.1"),
        contact=Contact(host, port),
        ssl_certificate=ssl_certificate,
        ssl_private_key=ssl_private_key,
        ssl_ca_chain=None,
    )

    config = PorterServerConfig(
        domain=Domain.MAINNET,
        identity_client=mock_identity_client,
        peer_client=MockPeerClient(mock_network, host),
        parent_logger=logger,
        storage=InMemoryStorage(),
        seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
        clock=mock_clock,
    )
    server = PorterServer(peer_server_config=peer_server_config, config=config)

    handle = mock_network.add_server(server)

    await handle.startup()
    yield server
    await handle.shutdown()
