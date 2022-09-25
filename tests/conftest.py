import itertools
import os
from typing import List, Iterator, AsyncIterator

import pytest
import trio

import nucypher_async.utils.logging as logging
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockClock, MockPeerClient
from nucypher_async.characters import Ursula
from nucypher_async.mocks import MockNetwork
from nucypher_async.drivers.identity import IdentityAddress, AmountT
from nucypher_async.domain import Domain
from nucypher_async.server import UrsulaServerConfig, UrsulaServer
from nucypher_async.drivers.peer import Contact, PeerHTTPServer
from nucypher_async.storage import InMemoryStorage


@pytest.fixture(scope="session")
def logger() -> logging.Logger:
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(level=logging.DEBUG, handlers=[logging.ConsoleHandler(stderr_at=None)])


@pytest.fixture
async def mock_clock() -> MockClock:
    return MockClock()


@pytest.fixture
def ursulas() -> Iterator[List[Ursula]]:
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_network(nursery: trio.Nursery) -> Iterator[MockNetwork]:
    yield MockNetwork(nursery)


@pytest.fixture
def mock_identity_client() -> Iterator[MockIdentityClient]:
    yield MockIdentityClient()


@pytest.fixture
def mock_payment_client() -> Iterator[MockPaymentClient]:
    yield MockPaymentClient()


@pytest.fixture
async def lonely_ursulas(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_payment_client: MockPaymentClient,
    ursulas: List[Ursula],
    logger: logging.Logger,
    mock_clock: MockClock,
) -> List[UrsulaServer]:
    servers = []

    for i in range(10):
        staking_provider_address = IdentityAddress(os.urandom(20))

        mock_identity_client.mock_set_up(
            staking_provider_address, ursulas[i].operator_address, AmountT.ether(40000)
        )

        config = UrsulaServerConfig(
            domain=Domain.MAINNET,
            contact=Contact("127.0.0.1", 9150 + i),
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=mock_identity_client,
            payment_client=mock_payment_client,
            peer_client=MockPeerClient(mock_network, "127.0.0.1"),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=[],
            clock=mock_clock,
        )

        server = await UrsulaServer.async_init(ursula=ursulas[i], config=config)
        servers.append(server)
        mock_network.add_server(PeerHTTPServer(server))

    return servers


@pytest.fixture
async def chain_seeded_ursulas(
    mock_network: MockNetwork, lonely_ursulas: List[UrsulaServer]
) -> AsyncIterator[List[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for server1, server2 in zip(lonely_ursulas[:-1], lonely_ursulas[1:]):
        server2.learner._test_set_seed_contacts([server1.secure_contact().contact])

    await mock_network.start_all()
    yield lonely_ursulas
    await mock_network.stop_all()


@pytest.fixture
async def fully_learned_ursulas(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    lonely_ursulas: List[UrsulaServer],
) -> AsyncIterator[List[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for server in lonely_ursulas:
        for other_server in lonely_ursulas:
            if other_server is server:
                continue

            peer_info = other_server._node  # TODO: add a proper method to UrsulaServer
            async with mock_identity_client.session() as session:
                stake = await session.get_staked_amount(peer_info.staking_provider_address)
            server.learner._test_add_verified_node(peer_info, stake)

    await mock_network.start_all()
    yield lonely_ursulas
    await mock_network.stop_all()
