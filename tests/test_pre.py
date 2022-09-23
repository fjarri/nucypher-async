from typing import List

import trio
import trio.testing

from nucypher_async.drivers.payment import AmountMATIC
from nucypher_async.domain import Domain
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.pre import Alice, Bob, encrypt
from nucypher_async.learner import Learner
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
        async with learner.verified_nodes_iter(addresses) as aiter:
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

    alice = Alice()
    bob = Bob()
    peer_client = MockPeerClient(mock_network, "127.0.0.1")

    alice_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
    )

    # Fund Alice
    mock_payment_client.mock_set_balance(alice.payment_address, AmountMATIC.ether(1))

    with trio.fail_after(10):
        policy = await alice.grant(
            learner=alice_learner,
            payment_client=mock_payment_client,
            bob=bob.public_info(),
            label=b"some label",
            threshold=2,
            shares=3,
            # TODO: using preselected Ursulas since blockchain is not implemeneted yet
            handpicked_addresses=[
                server._node.staking_provider_address for server in fully_learned_ursulas[:3]
            ],
        )

    message = b"a secret message"
    message_kit = encrypt(policy.encrypting_key, message)

    bob_learner = Learner(
        domain=Domain.MAINNET,
        peer_client=peer_client,
        identity_client=mock_identity_client,
        seed_contacts=[fully_learned_ursulas[0].secure_contact().contact],
    )

    with trio.fail_after(10):
        message_back = await bob.retrieve_and_decrypt(
            bob_learner,
            message_kit,
            policy.encrypted_treasure_map,
            remote_alice=alice.public_info(),
        )

    assert message_back == message
