import trio
import trio.testing

from nucypher_async.characters.pre import Delegator, Publisher, Recipient
from nucypher_async.client.porter import PorterClient
from nucypher_async.client.pre import encrypt, grant, retrieve_and_decrypt
from nucypher_async.domain import Domain
from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.mocks import (
    MockHTTPClient,
    MockIdentityClient,
    MockNetwork,
    MockPaymentClient,
    MockPeerClient,
)
from nucypher_async.p2p.learner import Learner
from nucypher_async.server import PorterServer, UrsulaServer


async def test_get_ursulas(
    mock_network: MockNetwork,
    fully_learned_ursulas: list[UrsulaServer],
    porter_server: PorterServer,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> None:
    mock_client = MockHTTPClient(mock_network, "127.0.0.1", porter_server.ssl_certificate())
    http_client = mock_client.as_httpx_async_client()
    porter_client = PorterClient("127.0.0.1", 9000, http_client)

    some_ursulas = [
        fully_learned_ursulas[3]._node.staking_provider_address,
        fully_learned_ursulas[7]._node.staking_provider_address,
    ]
    ursulas = await porter_client.get_ursulas(quantity=3, include_ursulas=some_ursulas)
    assert len(ursulas) == 3
    assert all(ursula in ursulas for ursula in some_ursulas)

    ursulas = await porter_client.get_ursulas(quantity=8, exclude_ursulas=some_ursulas)
    assert len(ursulas) == 8
    assert all(ursula not in ursulas for ursula in some_ursulas)


async def test_retrieve_cfrags(
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_payment_client: MockPaymentClient,
    fully_learned_ursulas: list[UrsulaServer],
    porter_server: PorterServer,
    autojump_clock: trio.testing.MockClock,  # noqa: ARG001
) -> None:
    mock_client = MockHTTPClient(mock_network, "127.0.0.1", porter_server.ssl_certificate())
    http_client = mock_client.as_httpx_async_client()
    porter_client = PorterClient("127.0.0.1", 9000, http_client)

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
    mock_payment_client.mock_set_balance(publisher.payment_address, AmountMATIC.ether(1))

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
            payment_client=mock_payment_client,
            handpicked_addresses=[
                server._node.staking_provider_address for server in fully_learned_ursulas[:3]
            ],
        )

    message = b"a secret message"
    message_kit = encrypt(policy, message)

    decrypted = await retrieve_and_decrypt(
        client=porter_client,
        message_kits=[message_kit],
        enacted_policy=enacted_policy,
        delegator_card=alice.card(),
        recipient=bob,
        publisher_card=publisher.card(),
    )

    assert decrypted == [message]
