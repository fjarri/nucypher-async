from typing import Optional, Iterable, Set, Union

from attrs import frozen
import arrow
import trio

from nucypher_core import (
    Address,
    TreasureMap,
    MessageKit,
    ReencryptionRequest,
    EncryptedTreasureMap,
    EncryptedKeyFrag,
)
from nucypher_core.umbral import (
    PublicKey,
    Capsule,
    VerifiedCapsuleFrag,
)

from ..drivers.identity import IdentityAddress
from ..drivers.payment import PaymentClient
from ..characters.pre import (
    Policy,
    RecipientCard,
    Publisher,
    DelegatorCard,
    PublisherCard,
    Recipient,
)
from ..p2p.learner import Learner
from ..p2p.verification import VerifiedUrsulaInfo


@frozen
class EnactedPolicy:
    encrypted_treasure_map: EncryptedTreasureMap
    encrypting_key: PublicKey
    start: arrow.Arrow
    end: arrow.Arrow


async def grant(
    policy: Policy,
    recipient_card: RecipientCard,
    publisher: Publisher,
    learner: Learner,
    payment_client: PaymentClient,
    handpicked_addresses: Optional[Iterable[IdentityAddress]] = None,
) -> EnactedPolicy:

    async with payment_client.session() as session:
        if await session.is_policy_active(policy.hrac):
            raise RuntimeError(f"Policy {policy.hrac} is already active")

    handpicked_addresses = set(handpicked_addresses) if handpicked_addresses else set()
    nodes = []
    async with learner.verified_nodes_iter(handpicked_addresses) as nodes_iter:
        async for node in nodes_iter:
            nodes.append(node)

    shares = len(policy.key_frags)
    if len(nodes) < shares:
        # TODO: implement ranking for granting, don't just pick random nodes
        async with learner.random_verified_nodes_iter(
            shares - len(nodes),
            # exclude=handpicked_addresses # TODO:
        ) as node_iter:
            async for node in node_iter:
                nodes.append(node)

    assigned_kfrags = {
        Address(bytes(node.staking_provider_address)): (node.encrypting_key, key_frag)
        for node, key_frag in zip(nodes, policy.key_frags)
    }

    encrypted_treasure_map = publisher.make_treasure_map(
        policy=policy, recipient_card=recipient_card, assigned_kfrags=assigned_kfrags
    )

    policy_start = learner._clock.utcnow()
    policy_end = policy_start.shift(days=30)  # TODO: make adjustable

    async with payment_client.session() as session:
        await session.create_policy(
            publisher.payment_signer,
            policy.hrac,
            shares,
            int(policy_start.timestamp()),
            int(policy_end.timestamp()),
        )

    return EnactedPolicy(
        start=policy_start,
        end=policy_end,
        encrypted_treasure_map=encrypted_treasure_map,
        encrypting_key=policy.encrypting_key,
    )


def encrypt(policy: Union[Policy, EnactedPolicy], message: bytes) -> MessageKit:
    return MessageKit(
        policy_encrypting_key=policy.encrypting_key, plaintext=message, conditions=None
    )


async def retrieve(
    learner: Learner,
    capsule: Capsule,
    treasure_map: TreasureMap,
    delegator_card: DelegatorCard,
    recipient_card: RecipientCard,
) -> Set[VerifiedCapsuleFrag]:

    responses: Set[VerifiedCapsuleFrag] = set()

    async def reencrypt(
        nursery: trio.Nursery, node: VerifiedUrsulaInfo, ekfrag: EncryptedKeyFrag
    ) -> None:
        request = ReencryptionRequest(
            capsules=[capsule],
            hrac=treasure_map.hrac,
            encrypted_kfrag=ekfrag,
            publisher_verifying_key=treasure_map.publisher_verifying_key,
            bob_verifying_key=recipient_card.verifying_key,
            conditions=None,
            context=None,
        )
        # TODO: why are we calling a private method here?
        response = await learner._peer_client.reencrypt(node.secure_contact, request)
        verified_cfrags = response.verify(
            capsules=request.capsules,
            alice_verifying_key=delegator_card.verifying_key,
            ursula_verifying_key=node.verifying_key,
            policy_encrypting_key=treasure_map.policy_encrypting_key,
            bob_encrypting_key=recipient_card.encrypting_key,
        )
        responses.add(verified_cfrags[0])
        if len(responses) == treasure_map.threshold:
            nursery.cancel_scope.cancel()

    destinations = {
        IdentityAddress(bytes(address)): ekfrag
        for address, ekfrag in treasure_map.destinations.items()
    }
    async with trio.open_nursery() as nursery:
        async with learner.verified_nodes_iter(destinations) as node_iter:
            async for node in node_iter:
                nursery.start_soon(
                    reencrypt,
                    nursery,
                    node,
                    destinations[node.staking_provider_address],
                )
    return responses


async def retrieve_and_decrypt(
    learner: Learner,
    message_kit: MessageKit,
    enacted_policy: EnactedPolicy,
    delegator_card: DelegatorCard,
    recipient: Recipient,
    publisher_card: PublisherCard,
) -> bytes:

    treasure_map = recipient.decrypt_treasure_map(
        enacted_policy.encrypted_treasure_map, publisher_card
    )

    vcfrags = await retrieve(
        learner=learner,
        capsule=message_kit.capsule,
        treasure_map=treasure_map,
        delegator_card=delegator_card,
        recipient_card=recipient.card(),
    )

    return recipient.decrypt_message_kit(
        message_kit=message_kit, treasure_map=treasure_map, vcfrags=vcfrags
    )
