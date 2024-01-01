import os
from pathlib import Path
from typing import AsyncIterator, Iterator, List, Tuple

import attrs
import pytest
import trio
from pons import (
    Amount,
    Client,
    DeployedContract,
    LocalProvider,
    SnapshotID,
    compile_contract_file,
)

import nucypher_async.utils.logging as logging
from nucypher_async.characters.pre import Ursula
from nucypher_async.domain import Domain
from nucypher_async.drivers.identity import AmountT, IdentityAddress
from nucypher_async.drivers.peer import Contact, UrsulaHTTPServer
from nucypher_async.mocks import (
    MockClock,
    MockHTTPServerHandle,
    MockIdentityClient,
    MockNetwork,
    MockPeerClient,
    MockPREClient,
)
from nucypher_async.server import (
    PorterServer,
    PorterServerConfig,
    UrsulaServer,
    UrsulaServerConfig,
)
from nucypher_async.storage import InMemoryStorage
from nucypher_async.utils.ssl import SSLCertificate, SSLPrivateKey


@pytest.fixture(scope="session")
def logger() -> logging.Logger:
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(level=logging.DEBUG, handlers=[logging.ConsoleHandler(stderr_at=None)])


@pytest.fixture
async def mock_clock() -> MockClock:
    return MockClock()


@pytest.fixture
def local_provider():
    return LocalProvider(root_balance=Amount.ether(100))


@attrs.frozen
class LocalContracts:
    snapshot: SnapshotID
    ritual_token: DeployedContract
    t_staking: DeployedContract
    taco_app: DeployedContract


@pytest.fixture(scope="session")
async def local_contracts(local_provider):
    RITUAL_TOKEN_SUPPLY = Amount.ether(10_000_000_000)
    MIN_AUTHORIZATION = Amount.ether(40_000)
    MIN_OPERATOR_SECONDS = 60 * 60 * 24  # one day in seconds
    REWARD_DURATION = 60 * 60 * 24 * 7  # one week in seconds
    DEAUTHORIZATION_DURATION = 60 * 60 * 24 * 60  # 60 days in seconds
    COMMITMENT_DURATION_1 = 182 * 60 * 24 * 60  # 182 days in seconds
    COMMITMENT_DURATION_2 = 2 * COMMITMENT_DURATION_1  # 365 days in seconds
    COMMITMENT_DEADLINE = 60 * 60 * 24 * 100  # 100 days after deploymwent

    contract_path = Path("/Users/bogdan/wb/github/nucypher-async-contracts")

    IMPORT_REMAPPINGS = {
        "@openzeppelin": contract_path / "openzeppelin-contracts",
        "@openzeppelin-upgradeable": contract_path / "openzeppelin-contracts-upgradeable",
        "@threshold": contract_path / "solidity-contracts",
    }

    RITUAL_TOKEN = compile_contract_file(
        contract_path / "RitualToken.sol", import_remappings=IMPORT_REMAPPINGS
    )["RitualToken"]

    TACO_APP = compile_contract_file(
        contract_path / "nucypher-contracts" / "contracts" / "contracts" / "TACoApplication.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["TACoApplication"]

    MOCK_T_STAKING = compile_contract_file(
        contract_path / "nucypher-contracts" / "contracts" / "test" / "TACoApplicationTestSet.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["ThresholdStakingForTACoApplicationMock"]

    client = Client(local_provider)
    async with client.session() as session:
        ritual_token = await session.deploy(
            root, RITUAL_TOKEN.constructor(RITUAL_TOKEN_SUPPLY.as_wei())
        )

        t_staking = await session.deploy(root, MOCK_T_STAKING.constructor())

        taco_app = await session.deploy(
            root,
            TACO_APP.constructor(
                _token=ritual_token.address,
                _tStaking=t_staking.address,
                _minimumAuthorization=MIN_AUTHORIZATION.as_wei(),
                _minOperatorSeconds=MIN_OPERATOR_SECONDS,
                _rewardDuration=REWARD_DURATION,
                _deauthorizationDuration=DEAUTHORIZATION_DURATION,
                _commitmentDurationOptions=[COMMITMENT_DURATION_1, COMMITMENT_DURATION_2],
                _commitmentDeadline=arrow.now().int_timestamp + COMMITMENT_DEADLINE,
            ),
        )

    snapshot = local_provider.take_snapshot()

    return LocalContracts(
        snapshot=snapshot, ritual_token=ritual_token, t_staking=t_staking, taco_app=taco_app
    )


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
def mock_pre_client() -> Iterator[MockPREClient]:
    yield MockPREClient()


@pytest.fixture
async def lonely_ursulas(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    ursulas: List[Ursula],
    logger: logging.Logger,
    mock_clock: MockClock,
) -> List[Tuple[MockHTTPServerHandle, UrsulaServer]]:
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
            pre_client=mock_pre_client,
            peer_client=MockPeerClient(mock_network, "127.0.0.1"),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=[],
            clock=mock_clock,
        )

        server = await UrsulaServer.async_init(ursula=ursulas[i], config=config)
        handle = mock_network.add_server(UrsulaHTTPServer(server))
        servers.append((handle, server))

    return servers


@pytest.fixture
async def chain_seeded_ursulas(
    mock_network: MockNetwork, lonely_ursulas: List[Tuple[MockHTTPServerHandle, UrsulaServer]]
) -> AsyncIterator[List[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for (_handle1, server1), (_handle2, server2) in zip(lonely_ursulas[:-1], lonely_ursulas[1:]):
        server2.learner._test_set_seed_contacts([server1.secure_contact().contact])

    for handle, _server in lonely_ursulas:
        await handle.startup()

    yield [server for _handle, server in lonely_ursulas]

    for handle, _server in lonely_ursulas:
        await handle.shutdown()


@pytest.fixture
async def fully_learned_ursulas(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    lonely_ursulas: List[Tuple[MockHTTPServerHandle, UrsulaServer]],
) -> AsyncIterator[List[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for _handle, server in lonely_ursulas:
        for _other_handle, other_server in lonely_ursulas:
            if other_server is server:
                continue

            peer_info = other_server._node  # TODO: add a proper method to UrsulaServer
            async with mock_identity_client.session() as session:
                stake = await session.get_staked_amount(peer_info.staking_provider_address)
            server.learner._test_add_verified_node(peer_info, stake)

    for handle, _server in lonely_ursulas:
        await handle.startup()

    yield [server for _handle, server in lonely_ursulas]

    for handle, _server in lonely_ursulas:
        await handle.shutdown()


@pytest.fixture
async def porter_server(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    fully_learned_ursulas: List[UrsulaServer],
    logger: logging.Logger,
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
        ssl_ca_chain=None,
        identity_client=mock_identity_client,
        peer_client=MockPeerClient(mock_network, host),
        parent_logger=logger,
        storage=InMemoryStorage(),
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
        clock=mock_clock,
    )
    server = PorterServer(config)

    handle = mock_network.add_server(server)

    await handle.startup()
    yield server
    await handle.shutdown()
