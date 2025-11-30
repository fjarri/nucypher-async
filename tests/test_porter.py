import trio
import trio.testing

from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.network import NetworkClient
from nucypher_async.client.porter import PorterClient
from nucypher_async.client.pre import LocalPREClient, ProxyPREClient, pre_encrypt
from nucypher_async.domain import Domain
from nucypher_async.drivers.pre import PREAccount, PREAccountSigner, PREAmount
from nucypher_async.mocks import (
    MockClock,
    MockHTTPClient,
    MockIdentityClient,
    MockNetwork,
    MockPeerClient,
    MockPREClient,
)
from nucypher_async.server import NodeServer, PorterServer


async def test_get_nodes(
    mock_network: MockNetwork,
    fully_learned_nodes: list[NodeServer],
    porter_server: PorterServer,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> None:
    mock_client = MockHTTPClient(
        mock_network, "127.0.0.1", porter_server.secure_contact().public_key._as_ssl_certificate()
    )
    http_client = mock_client.as_httpx_async_client()
    porter_client = PorterClient("127.0.0.1", 9000, http_client)

    some_nodes = [
        fully_learned_nodes[3]._node.staking_provider_address,
        fully_learned_nodes[7]._node.staking_provider_address,
    ]
    nodes = await porter_client.get_nodes(quantity=3, include_nodes=some_nodes)
    assert len(nodes) == 3
    assert all(node in nodes for node in some_nodes)

    nodes = await porter_client.get_nodes(quantity=8, exclude_nodes=some_nodes)
    assert len(nodes) == 8
    assert all(node not in nodes for node in some_nodes)


async def test_retrieve_cfrags(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_pre_client: MockPREClient,
    fully_learned_nodes: list[NodeServer],
    porter_server: PorterServer,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
    mock_clock: MockClock,
) -> None:
    mock_client = MockHTTPClient(
        mock_network, "127.0.0.1", porter_server.secure_contact().public_key._as_ssl_certificate()
    )
    http_client = mock_client.as_httpx_async_client()

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

    bob_client = ProxyPREClient(
        "127.0.0.1",
        9000,
        http_client,
    )

    decrypted = await bob_client.decrypt(
        recipient=bob,
        enacted_policy=enacted_policy,
        message_kit=message_kit,
        delegator_card=alice.card(),
        publisher_card=publisher.card(),
    )

    assert decrypted == message
