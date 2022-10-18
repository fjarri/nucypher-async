from typing import List

import trio
import trio.testing

from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.domain import Domain
from nucypher_async.server import UrsulaServer
from nucypher_async.characters.pre import Delegator, Recipient, Publisher
from nucypher_async.client.pre import grant, retrieve_and_decrypt, encrypt
from nucypher_async.p2p.learner import Learner
from nucypher_async.p2p.algorithms import verified_nodes_iter
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockPeerClient, MockNetwork
from nucypher_async.utils.logging import Logger


async def test_verified_nodes_iter(
    nursery: trio.Nursery,
    autojump_clock: trio.testing.MockClock,
    fully_learned_ursulas: List[UrsulaServer],
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    logger: Logger,
) -> None:

    peer_client = MockPeerClient(mock_network, "127.0.0.1")
    learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
        parent_logger=logger,
    )

    addresses = [server._node.staking_provider_address for server in fully_learned_ursulas[:3]]
    nodes = []

    with trio.fail_after(10):
        async with verified_nodes_iter(learner, addresses) as aiter:
            async for node in aiter:
                nodes.append(node)

    assert len(nodes) == 3


async def test_granting(
    nursery: trio.Nursery,
    autojump_clock: trio.testing.MockClock,
    fully_learned_ursulas: List[UrsulaServer],
    mock_network: MockNetwork,
    mock_identity_client: MockIdentityClient,
    mock_payment_client: MockPaymentClient,
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

    bob_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
    )

    with trio.fail_after(10):
        message_back = await retrieve_and_decrypt(
            learner=bob_learner,
            message_kit=message_kit,
            enacted_policy=enacted_policy,
            delegator_card=alice.card(),
            recipient=bob,
            publisher_card=publisher.card(),
        )

    assert message_back == message
