import trio
import trio.testing
from conftest import LocalContracts

from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.pre import encrypt, grant, retrieve_and_decrypt
from nucypher_async.domain import Domain
from nucypher_async.drivers.identity import IdentityClient
from nucypher_async.drivers.pre import AmountMATIC
from nucypher_async.mocks import (
    MockHTTPServerHandle,
    MockIdentityClient,
    MockNetwork,
    MockPeerClient,
    MockPREClient,
)
from nucypher_async.p2p.algorithms import verified_nodes_iter
from nucypher_async.p2p.learner import Learner
from nucypher_async.server import UrsulaServer
from nucypher_async.utils.logging import Logger


async def test_verified_nodes_iter(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_ursulas: list[UrsulaServer],
    mock_network: MockNetwork,
    # mock_identity_client: MockIdentityClient,
    logger: Logger,
    clean_local_contracts: LocalContracts,
    local_identity_client: IdentityClient,
) -> None:
    peer_client = MockPeerClient(mock_network, "127.0.0.1")
    learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=local_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
        parent_logger=logger,
    )

    addresses = [server._node.staking_provider_address for server in fully_learned_ursulas[:3]]
    nodes = []

    with trio.fail_after(10):
        async with verified_nodes_iter(learner, addresses) as verified_nodes:
            async for node in verified_nodes:
                nodes.append(node)

    assert len(nodes) == 3


async def test_node_setup(lonely_ursulas: list[tuple[MockHTTPServerHandle, UrsulaServer]]) -> None:
    pass


async def test_granting(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_ursulas: list[UrsulaServer],
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
) -> None:
    alice = Delegator.random()
    publisher = Publisher.random()
    bob = Recipient.random()
    peer_client = MockPeerClient(mock_network, "127.0.0.1")

    alice_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
    )

    # Fund Alice
    mock_pre_client.mock_set_balance(publisher.pre_address, AmountMATIC.ether(1))

    policy = alice.make_policy(
        recipient_card=bob.card(),
        label=b"some label",
        threshold=2,
        shares=3,
    )

    with trio.fail_after(10):
        enacted_policy = await grant(
            policy=policy,
            recipient_card=bob.card(),
            publisher=publisher,
            learner=alice_learner,
            pre_client=mock_pre_client,
            handpicked_addresses=[
                server._node.staking_provider_address for server in fully_learned_ursulas[:3]
            ],
        )

    message = b"a secret message"
    message_kit = encrypt(policy, message)

    bob_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
    )

    with trio.fail_after(10):
        decrypted = await retrieve_and_decrypt(
            client=bob_learner,
            message_kits=[message_kit],
            enacted_policy=enacted_policy,
            delegator_card=alice.card(),
            recipient=bob,
            publisher_card=publisher.card(),
        )

    assert decrypted == [message]
