import trio
import trio.testing

from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.pre import LocalPREClient, pre_encrypt
from nucypher_async.domain import Domain
from nucypher_async.drivers.pre import PREAccount, PREAccountSigner, PREAmount
from nucypher_async.mocks import (
    MockClock,
    MockIdentityClient,
    MockNetwork,
    MockPeerClient,
    MockPREClient,
)
from nucypher_async.server import NodeServer
from nucypher_async.utils.logging import Logger


async def test_verified_nodes_iter(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_nodes: list[NodeServer],
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    logger: Logger,
    mock_clock: MockClock,
) -> None:
    peer_client = MockPeerClient(mock_network, "127.0.0.1")
    network_client = NetworkClient(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
        parent_logger=logger,
        clock=mock_clock,
    )

    addresses = [server._node.staking_provider_address for server in fully_learned_nodes[:3]]
    nodes = []

    with trio.fail_after(10):
        async for node_info in network_client.verified_nodes_iter(addresses):
            nodes.append(node_info)

    assert len(nodes) == 3


async def test_granting(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_nodes: list[NodeServer],
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    mock_clock: MockClock,
    logger: Logger,
) -> None:
    alice = Delegator.random()
    publisher = Publisher.random()
    publisher_signer = PREAccountSigner(PREAccount.random())
    bob = Recipient.random()
    peer_client = MockPeerClient(mock_network, "127.0.0.1")

    publisher_client = LocalPREClient(
        NetworkClient(
            peer_client=peer_client,
            identity_client=mock_identity_client,
            seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
            domain=Domain.MAINNET,
            clock=mock_clock,
            parent_logger=logger.get_child("Publisher"),
        ),
        pre_client=mock_pre_client,
    )

    # Fund the publisher
    mock_pre_client.mock_set_balance(publisher_signer.address, PREAmount.ether(1))

    policy = alice.make_policy(
        recipient_card=bob.card(),
        label=b"some label",
        threshold=2,
        shares=3,
    )

    with trio.fail_after(10):
        enacted_policy = await publisher_client.grant(
            publisher=publisher,
            signer=publisher_signer,
            policy=policy,
            recipient_card=bob.card(),
        )

    message = b"a secret message"
    message_kit = pre_encrypt(policy, message)

    bob_client = LocalPREClient(
        NetworkClient(
            peer_client=peer_client,
            identity_client=mock_identity_client,
            seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
            domain=Domain.MAINNET,
            clock=mock_clock,
            parent_logger=logger.get_child("Recipient"),
        ),
        pre_client=mock_pre_client,
    )

    with trio.fail_after(10):
        decrypted = await bob_client.decrypt(
            recipient=bob,
            enacted_policy=enacted_policy,
            message_kit=message_kit,
            delegator_card=alice.card(),
            publisher_card=publisher.card(),
        )

    assert decrypted == message
