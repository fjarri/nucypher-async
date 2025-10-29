import itertools
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import arrow
import attrs
import pytest
import trio
from ethereum_rpc import Amount
from pons import AccountSigner, Client, DeployedContract
from pons.compiler import compile_contract_file
from pons.local_provider import LocalProvider, SnapshotID

from nucypher_async.characters.pre import Ursula
from nucypher_async.domain import Domain
from nucypher_async.drivers.identity import AmountT, IdentityAddress, IdentityClient
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
    PeerServerConfig,
    PorterServer,
    PorterServerConfig,
    UrsulaServer,
    UrsulaServerConfig,
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


@attrs.frozen
class LocalContracts:
    provider: LocalProvider
    snapshot_clean: SnapshotID
    ritual_token: DeployedContract
    t_staking: DeployedContract
    taco_app: DeployedContract
    taco_child_app: DeployedContract
    coordinator: DeployedContract


@pytest.fixture(scope="session")
def local_contracts() -> LocalContracts:
    RITUAL_TOKEN_SUPPLY = Amount.ether(10_000_000_000)
    MIN_AUTHORIZATION = Amount.ether(40_000)
    MIN_OPERATOR_SECONDS = 60 * 60 * 24  # one day in seconds
    REWARD_DURATION = 60 * 60 * 24 * 7  # one week in seconds
    DEAUTHORIZATION_DURATION = 60 * 60 * 24 * 60  # 60 days in seconds
    COMMITMENT_DURATION_1 = 182 * 60 * 24 * 60  # 182 days in seconds
    COMMITMENT_DURATION_2 = 2 * COMMITMENT_DURATION_1  # 365 days in seconds
    COMMITMENT_DEADLINE = 60 * 60 * 24 * 100  # 100 days after deploymwent
    # Coordinator
    TIMEOUT = 3600
    MAX_DKG_SIZE = 8
    FEE_RATE = 1

    contract_path = Path(__file__).parent.parent / "contracts"

    IMPORT_REMAPPINGS = {
        "@openzeppelin": contract_path / "openzeppelin-contracts",
        "@openzeppelin-upgradeable": contract_path / "openzeppelin-contracts-upgradeable",
        "@threshold": contract_path / "solidity-contracts",
    }

    PROXY = compile_contract_file(
        contract_path
        / "openzeppelin-contracts"
        / "contracts"
        / "proxy"
        / "transparent"
        / "TransparentUpgradeableProxy.sol",
        optimize=True,
    )["TransparentUpgradeableProxy"]

    RITUAL_TOKEN = compile_contract_file(
        contract_path / "RitualToken.sol", import_remappings=IMPORT_REMAPPINGS
    )["RitualToken"]

    TACO_APP = compile_contract_file(
        contract_path / "nucypher-contracts" / "contracts" / "contracts" / "TACoApplication.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["TACoApplication"]

    TACO_CHILD_APP = compile_contract_file(
        contract_path
        / "nucypher-contracts"
        / "contracts"
        / "contracts"
        / "coordination"
        / "TACoChildApplication.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["TACoChildApplication"]

    MOCK_T_STAKING = compile_contract_file(
        contract_path
        / "nucypher-contracts"
        / "contracts"
        / "contracts"
        / "TestnetThresholdStaking.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["TestnetThresholdStaking"]

    COORDINATOR = compile_contract_file(
        contract_path
        / "nucypher-contracts"
        / "contracts"
        / "contracts"
        / "coordination"
        / "Coordinator.sol",
        import_remappings=IMPORT_REMAPPINGS,
        optimize=True,
    )["Coordinator"]

    provider = LocalProvider(root_balance=Amount.ether(100))
    root = provider.root
    client = Client(provider)

    # Currently Client only has async API, and async fixtures can only be function-scoped.
    # So we need to run the async part manually.
    contracts = None

    async def deploy_contracts() -> None:
        nonlocal contracts

        staking_provider = AccountSigner.create()

        async with client.session() as session:
            ritual_token = await session.deploy(
                root, RITUAL_TOKEN.constructor(RITUAL_TOKEN_SUPPLY.as_wei())
            )

            t_staking = await session.deploy(root, MOCK_T_STAKING.constructor())

            taco_app_logic = await session.deploy(
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

            taco_app_proxy = await session.deploy(
                root,
                PROXY.constructor(
                    _logic=taco_app_logic.address, initialOwner=root.address, _data=b""
                ),
            )

            taco_app = DeployedContract(taco_app_logic.abi, taco_app_proxy.address)

            taco_child_app_logic = await session.deploy(
                root,
                TACO_CHILD_APP.constructor(
                    _rootApplication=taco_app.address,
                    _minimumAuthorization=MIN_AUTHORIZATION.as_wei(),
                ),
            )

            taco_child_app_proxy = await session.deploy(
                root,
                PROXY.constructor(
                    _logic=taco_child_app_logic.address, initialOwner=root.address, _data=b""
                ),
            )

            taco_child_app = DeployedContract(
                taco_child_app_logic.abi, taco_child_app_proxy.address
            )

            await session.transact(root, taco_app.method.initialize())

            await session.transact(
                root,
                t_staking.method.setApplication(
                    _application=taco_app.address,
                ),
            )

            await session.transact(
                root,
                taco_app.method.setChildApplication(
                    _childApplication=taco_child_app.address,
                ),
            )

            # Deploy Coordinator

            coordinator_logic = await session.deploy(
                root,
                COORDINATOR.constructor(
                    _application=taco_child_app.address,
                    _currency=ritual_token.address,
                    _feeRatePerSecond=FEE_RATE,
                ),
            )

            encoded_initializer_function = coordinator_logic.method.initialize(
                _timeout=TIMEOUT, _maxDkgSize=MAX_DKG_SIZE, _admin=root.address
            ).data_bytes

            coordinator_proxy = await session.deploy(
                root,
                PROXY.constructor(
                    _logic=coordinator_logic.address,
                    initialOwner=root.address,
                    _data=encoded_initializer_function,
                ),
            )

            coordinator = DeployedContract(coordinator_logic.abi, coordinator_proxy.address)

            await session.transact(root, coordinator.method.makeInitiationPublic())
            await session.transact(
                root, taco_child_app.method.initialize(_coordinator=coordinator.address)
            )

        snapshot = provider.take_snapshot()
        contracts = LocalContracts(
            provider=provider,
            snapshot_clean=snapshot,
            ritual_token=ritual_token,
            t_staking=t_staking,
            taco_app=taco_app,
            taco_child_app=taco_child_app,
            coordinator=coordinator,
        )

    trio.run(deploy_contracts)

    assert contracts is not None
    return contracts


@pytest.fixture
def clean_local_contracts(local_contracts: LocalContracts) -> LocalContracts:
    local_contracts.provider.revert_to_snapshot(local_contracts.snapshot_clean)
    return local_contracts


@pytest.fixture
def local_identity_client(local_contracts: LocalContracts) -> IdentityClient:
    return IdentityClient(
        Client(local_contracts.provider),
        local_contracts.taco_app.address,
        local_contracts.t_staking.address,
        local_contracts.coordinator.address,
    )


@pytest.fixture
def ursulas() -> Iterator[list[Ursula]]:
    yield [Ursula() for i in range(10)]


@pytest.fixture
def mock_network(nursery: trio.Nursery) -> MockNetwork:
    return MockNetwork(nursery)


@pytest.fixture
def mock_identity_client() -> MockIdentityClient:
    return MockIdentityClient()


@pytest.fixture
def mock_pre_client() -> Iterator[MockPREClient]:
    yield MockPREClient()


@pytest.fixture
async def lonely_ursulas(
    mock_network: MockNetwork,
    local_contracts: LocalContracts,
    local_identity_client: IdentityClient,
    # mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    ursulas: list[Ursula],
    logger: logging.Logger,
    mock_clock: MockClock,
) -> list[tuple[MockHTTPServerHandle, UrsulaServer]]:
    servers = []

    for i in range(10):
        staking_provider = AccountSigner.create()

        async with Client(local_contracts.provider).session() as session:
            await session.transfer(
                local_contracts.provider.root, staking_provider.address, Amount.ether(1)
            )
            await session.transfer(
                local_contracts.provider.root, ursulas[i].operator_address, Amount.ether(1)
            )

        async with local_identity_client.session() as session:
            await session.add_staking_provider(
                owner_signer=local_contracts.provider.root,
                staking_provider_signer=staking_provider,
                operator_address=ursulas[i].operator_address,
                stake=AmountT.ether(40000),
            )

            await session.confirm_operator_address(
                operator_signer=ursulas[i].identity_account.signer, public_key=ursulas[i].dkg_key
            )

        peer_server_config = PeerServerConfig(
            bind_as="127.0.0.1",
            contact=Contact("127.0.0.1", 9150 + i),
            ssl_certificate=None,
            ssl_private_key=None,
            ssl_ca_chain=None,
        )

        config = UrsulaServerConfig(
            domain=Domain.MAINNET,
            # TODO: find a way to ensure the client's domains correspond to the domain set above
            identity_client=local_identity_client,
            pre_client=mock_pre_client,
            peer_client=MockPeerClient(mock_network, "127.0.0.1"),
            parent_logger=logger.get_child(str(i)),
            storage=InMemoryStorage(),
            seed_contacts=[],
            clock=mock_clock,
        )

        server = await UrsulaServer.async_init(
            ursula=ursulas[i], peer_server_config=peer_server_config, config=config
        )
        handle = mock_network.add_server(UrsulaHTTPServer(server))
        servers.append((handle, server))

    return servers


@pytest.fixture
async def chain_seeded_ursulas(
    lonely_ursulas: list[tuple[MockHTTPServerHandle, UrsulaServer]],
) -> AsyncIterator[list[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for (_handle1, server1), (_handle2, server2) in itertools.pairwise(lonely_ursulas):
        server2.learner._test_set_seed_contacts([server1.secure_contact().contact])

    for handle, _server in lonely_ursulas:
        await handle.startup()

    yield [server for _handle, server in lonely_ursulas]

    for handle, _server in lonely_ursulas:
        await handle.shutdown()


@pytest.fixture
async def fully_learned_ursulas(
    mock_network: MockNetwork,
    # mock_identity_client: MockIdentityClient,
    local_identity_client: IdentityClient,
    lonely_ursulas: list[tuple[MockHTTPServerHandle, UrsulaServer]],
) -> AsyncIterator[list[UrsulaServer]]:
    # Each Ursula knows only about one other Ursula,
    # but the graph is fully connected.
    for _handle, server in lonely_ursulas:
        for _other_handle, other_server in lonely_ursulas:
            if other_server is server:
                continue

            peer_info = other_server._node  # TODO: add a proper method to UrsulaServer
            async with local_identity_client.session() as session:
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
    local_identity_client: IdentityClient,
    # mock_identity_client: MockIdentityClient,
    fully_learned_ursulas: list[UrsulaServer],
    logger: logging.Logger,
    mock_clock: MockClock,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> AsyncIterator[PorterServer]:
    host = "127.0.0.1"
    port = 9000
    ssl_private_key = SSLPrivateKey.from_seed(b"1231234")
    ssl_certificate = SSLCertificate.self_signed(mock_clock.utcnow(), ssl_private_key, host)

    peer_server_config = PeerServerConfig(
        bind_as="127.0.0.1",
        contact=Contact(host, port),
        ssl_certificate=ssl_certificate,
        ssl_private_key=ssl_private_key,
        ssl_ca_chain=None,
    )

    config = PorterServerConfig(
        domain=Domain.MAINNET,
        identity_client=local_identity_client,
        peer_client=MockPeerClient(mock_network, host),
        parent_logger=logger,
        storage=InMemoryStorage(),
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
        clock=mock_clock,
    )
    server = PorterServer(peer_server_config=peer_server_config, config=config)

    handle = mock_network.add_server(server)

    await handle.startup()
    yield server
    await handle.shutdown()
