import itertools
import os
from collections.abc import AsyncIterator
from ipaddress import IPv4Address

import pytest
import trio

from nucypher_async.characters.cbd import Decryptor
from nucypher_async.characters.node import Operator
from nucypher_async.characters.pre import Reencryptor
from nucypher_async.domain import Domain
from nucypher_async.drivers.identity import AmountT, IdentityAccount, IdentityAddress
from nucypher_async.master_key import MasterKey
from nucypher_async.mocks import (
    MockCBDClient,
    MockClock,
    MockHTTPClient,
    MockHTTPNetwork,
    MockIdentityClient,
    MockNodeClient,
    MockNodeServerHandle,
    MockP2PNetwork,
    MockPREClient,
)
from nucypher_async.node import HTTPServerConfig, NodeServer, NodeServerConfig, SSLConfig
from nucypher_async.node_base import Contact
from nucypher_async.proxy import ProxyServer, ProxyServerConfig
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils import logging
from nucypher_async.utils.ssl import SSLCertificate, SSLPrivateKey


@pytest.fixture(scope="session")
def logger() -> logging.Logger:
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(
        level=logging.DEBUG, handlers=[logging.ConsoleHandler(stderr_at=None)], clock=MockClock()
    )


@pytest.fixture
async def mock_clock() -> MockClock:
    return MockClock()


@pytest.fixture
def master_keys() -> list[MasterKey]:
    return [MasterKey.random() for _ in range(10)]


@pytest.fixture
def identity_accounts() -> list[IdentityAccount]:
    return [IdentityAccount.random() for _ in range(10)]


@pytest.fixture
def operators(
    master_keys: list[MasterKey], identity_accounts: list[IdentityAccount]
) -> list[Operator]:
    return [
        Operator(master_key, identity_account)
        for master_key, identity_account in zip(master_keys, identity_accounts, strict=True)
    ]


@pytest.fixture
def reencryptors(master_keys: list[MasterKey]) -> list[Reencryptor]:
    return [Reencryptor(master_key) for master_key in master_keys]


@pytest.fixture
def decryptors(master_keys: list[MasterKey]) -> list[Decryptor]:
    return [Decryptor(master_key) for master_key in master_keys]


@pytest.fixture
def mock_p2p_network(nursery: trio.Nursery) -> MockP2PNetwork:
    return MockP2PNetwork(nursery)


@pytest.fixture
def mock_http_network(nursery: trio.Nursery) -> MockHTTPNetwork:
    return MockHTTPNetwork(nursery)


@pytest.fixture
def mock_passive_http_client(mock_http_network: MockHTTPNetwork) -> MockHTTPClient:
    return MockHTTPClient(mock_http_network, host=None)


@pytest.fixture
def mock_passive_node_client(mock_p2p_network: MockP2PNetwork) -> MockNodeClient:
    return MockNodeClient(mock_p2p_network, contact=None)


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
    mock_p2p_network: MockP2PNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    mock_cbd_client: MockCBDClient,
    operators: list[Operator],
    reencryptors: list[Reencryptor],
    decryptors: list[Decryptor],
    logger: logging.Logger,
    mock_clock: MockClock,
) -> list[tuple[MockNodeServerHandle, NodeServer]]:
    servers = []

    for i in range(10):
        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_set_up(
            staking_provider_address, operators[i].address, AmountT.ether(40000)
        )

        node_logger = logger.get_child(str(i))

        http_server_config = HTTPServerConfig.from_typed_values(
            bind_to_address=IPv4Address("127.0.0.1"),
            bind_to_port=9150 + i,
        )

        contact = Contact(str(http_server_config.bind_to_address), http_server_config.bind_to_port)

        config = NodeServerConfig.from_typed_values(
            http_server_config=http_server_config,
            domain=Domain.MAINNET,
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=mock_identity_client,
            pre_client=mock_pre_client,
            cbd_client=mock_cbd_client,
            node_client=MockNodeClient(mock_p2p_network, contact),
            logger=node_logger,
            clock=mock_clock,
        )

        server = await NodeServer.async_init(
            config=config,
            operator=operators[i],
            reencryptor=reencryptors[i],
            decryptor=decryptors[i],
        )
        handle = mock_p2p_network.add_server(server)
        servers.append((handle, server))

    return servers


@pytest.fixture
async def chain_seeded_nodes(
    lonely_nodes: list[tuple[MockNodeServerHandle, NodeServer]],
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
    lonely_nodes: list[tuple[MockNodeServerHandle, NodeServer]],
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
async def proxy_server(
    mock_p2p_network: MockP2PNetwork,
    mock_http_network: MockHTTPNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    mock_cbd_client: MockCBDClient,
    fully_learned_nodes: list[NodeServer],
    logger: logging.Logger,
    mock_clock: MockClock,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> AsyncIterator[ProxyServer]:
    host = "127.0.0.1"
    port = 9000

    ssl_private_key = SSLPrivateKey.from_seed(b"1231234")
    ssl_certificate = SSLCertificate.self_signed(mock_clock.utcnow(), ssl_private_key, host)

    ssl_config = SSLConfig(private_key=ssl_private_key, certificate=ssl_certificate, ca_chain=[])

    logger = logger.get_child("ProxyServer")

    http_server_config = HTTPServerConfig.from_typed_values(
        bind_to_address=IPv4Address(host),
        bind_to_port=port,
        ssl_config=ssl_config,
    )

    config = ProxyServerConfig(
        http_server_config=http_server_config,
        domain=Domain.MAINNET,
        identity_client=mock_identity_client,
        pre_client=mock_pre_client,
        cbd_client=mock_cbd_client,
        node_client=MockNodeClient(mock_p2p_network),
        logger=logger,
        storage=InMemoryStorage(),
        seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
        clock=mock_clock,
    )

    server = ProxyServer(config)

    handle = mock_http_network.add_server(server)

    await handle.startup()
    yield server
    await handle.shutdown()
