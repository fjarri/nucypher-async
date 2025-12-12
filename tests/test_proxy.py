from collections.abc import Callable

import trio
import trio.testing

from nucypher_async._mocks import MockPREClient
from nucypher_async.blockchain.pre import PREAccount, PREAccountSigner, PREAmount
from nucypher_async.characters.pre import Delegator, EncryptedMessage, Publisher, Recipient
from nucypher_async.client.pre import LocalPREClient
from nucypher_async.node import NodeServer
from nucypher_async.proxy import ProxyPREClient
from nucypher_async.proxy._client import ProxyClient


async def test_get_nodes(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    fully_learned_nodes: list[NodeServer],
    proxy_client: ProxyClient,
) -> None:
    some_nodes = [
        fully_learned_nodes[3].info.staking_provider_address,
        fully_learned_nodes[7].info.staking_provider_address,
    ]
    nodes = await proxy_client.get_nodes(quantity=3, include_nodes=some_nodes)
    assert len(nodes) == 3
    assert all(node in nodes for node in some_nodes)

    nodes = await proxy_client.get_nodes(quantity=8, exclude_nodes=some_nodes)
    assert len(nodes) == 8
    assert all(node not in nodes for node in some_nodes)


async def test_retrieve_cfrags(
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    mock_pre_client: MockPREClient,
    proxy_pre_client: ProxyPREClient,
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
    encrypted_message = EncryptedMessage(policy, message)

    decrypted = await proxy_pre_client.decrypt(
        recipient=bob,
        enacted_policy=enacted_policy,
        encrypted_message=encrypted_message,
        delegator_card=alice.card(),
        publisher_card=publisher.card(),
    )

    assert decrypted == message
