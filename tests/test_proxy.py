import trio
import trio.testing

from nucypher_async._mocks import (
    MockClock,
    MockHTTPClient,
    MockIdentityClient,
    MockNodeClient,
    MockPREClient,
)
from nucypher_async.blockchain.pre import PREAccount, PREAccountSigner, PREAmount
from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.pre import LocalPREClient, pre_encrypt
from nucypher_async.domain import Domain
from nucypher_async.node import NodeServer
from nucypher_async.proxy import ProxyPREClient, ProxyServer
from nucypher_async.proxy.client import ProxyClient


async def test_get_nodes(
    mock_passive_http_client: MockHTTPClient,
    fully_learned_nodes: list[NodeServer],
    # TODO: make the fixture return a handle or something, so we can actually use it?
    # Or `ProxyClient`?
    proxy_server: ProxyServer,  # noqa: ARG001
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> None:
    proxy_client = ProxyClient("127.0.0.1", 9000, mock_passive_http_client)

    some_nodes = [
        fully_learned_nodes[3]._node.staking_provider_address,
        fully_learned_nodes[7]._node.staking_provider_address,
    ]
    nodes = await proxy_client.get_nodes(quantity=3, include_nodes=some_nodes)
    assert len(nodes) == 3
    assert all(node in nodes for node in some_nodes)

    nodes = await proxy_client.get_nodes(quantity=8, exclude_nodes=some_nodes)
    assert len(nodes) == 8
    assert all(node not in nodes for node in some_nodes)


async def test_retrieve_cfrags(
    mock_passive_node_client: MockNodeClient,
    mock_passive_http_client: MockHTTPClient,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    fully_learned_nodes: list[NodeServer],
    proxy_server: ProxyServer,  # noqa: ARG001
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    mock_clock: MockClock,
) -> None:
    alice = Delegator.random()
    publisher = Publisher.random()
    publisher_signer = PREAccountSigner(PREAccount.random())
    bob = Recipient.random()

    publisher_client = LocalPREClient(
        NetworkClient(
            node_client=mock_passive_node_client,
            identity_client=mock_identity_client,
            seed_contacts=[fully_learned_nodes[0].secure_contact().contact],
            domain=Domain.MAINNET,
            clock=mock_clock,
        ),
        mock_pre_client,
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

    bob_client = ProxyPREClient("127.0.0.1", 9000, mock_passive_http_client)

    decrypted = await bob_client.decrypt(
        recipient=bob,
        enacted_policy=enacted_policy,
        message_kit=message_kit,
        delegator_card=alice.card(),
        publisher_card=publisher.card(),
    )

    assert decrypted == message
