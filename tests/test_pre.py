from collections.abc import Callable

import trio
import trio.testing

from nucypher_async._mocks import MockPREClient
from nucypher_async.blockchain.pre import PREAccount, PREAccountSigner, PREAmount
from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.pre import LocalPREClient, pre_encrypt
from nucypher_async.node import NodeServer


async def test_verified_nodes_iter(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_nodes: list[NodeServer],
    network_client_factory: Callable[[str], NetworkClient],
) -> None:
    network_client = network_client_factory("")
    addresses = [server._node.staking_provider_address for server in fully_learned_nodes[:3]]
    nodes = []

    with trio.fail_after(10):
        async for node_info in network_client.verified_nodes_iter(addresses):
            nodes.append(node_info)

    assert len(nodes) == 3


async def test_granting(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    mock_pre_client: MockPREClient,
    local_pre_client_factory: Callable[[str], LocalPREClient],
) -> None:
    alice = Delegator.random()
    publisher = Publisher.random()
    publisher_signer = PREAccountSigner(PREAccount.random())
    bob = Recipient.random()

    publisher_client = local_pre_client_factory("Publisher")

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

    bob_client = local_pre_client_factory("Recipient")

    with trio.fail_after(10):
        decrypted = await bob_client.decrypt(
            recipient=bob,
            enacted_policy=enacted_policy,
            message_kit=message_kit,
            delegator_card=alice.card(),
            publisher_card=publisher.card(),
        )

    assert decrypted == message
