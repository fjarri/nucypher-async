from typing import Optional, Iterable, Union, Dict, List, Mapping

from attrs import frozen
import arrow
import trio

from nucypher_core import (
    Address,
    TreasureMap,
    MessageKit,
    EncryptedTreasureMap,
    RetrievalKit,
    Conditions,
    Context,
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
from ..p2p.algorithms import verified_nodes_iter, get_ursulas
from ..p2p.verification import VerifiedUrsulaInfo
from .porter import PorterClient


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
    shares = len(policy.key_frags)

    nodes = await get_ursulas(
        learner=learner,
        quantity=shares,
        include_ursulas=handpicked_addresses,
    )

    assigned_kfrags = {
        Address(bytes(node.staking_provider_address)): (node.encrypting_key, key_frag)
        for node, key_frag in zip(nodes, policy.key_frags)
    }

    encrypted_treasure_map = publisher.make_treasure_map(
        policy=policy, recipient_card=recipient_card, assigned_kfrags=assigned_kfrags
    )

    policy_start = learner.clock.utcnow()
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


@frozen
class RetrievalState:
    retrieval_kit: RetrievalKit
    vcfrags: Dict[IdentityAddress, VerifiedCapsuleFrag]

    @classmethod
    def from_message_kit(cls, message_kit: MessageKit) -> "RetrievalState":
        return cls(RetrievalKit.from_message_kit(message_kit), {})

    def with_vcfrags(
        self, vcfrags: Mapping[IdentityAddress, VerifiedCapsuleFrag]
    ) -> "RetrievalState":
        old_rkit = self.retrieval_kit
        addresses = {Address(bytes(address)) for address in vcfrags}
        new_queried_addresses = old_rkit.queried_addresses | addresses
        new_rkit = RetrievalKit(old_rkit.capsule, new_queried_addresses, old_rkit.conditions)
        new_vcfrags = dict(self.vcfrags)
        new_vcfrags.update(vcfrags)
        return RetrievalState(new_rkit, new_vcfrags)


async def retrieve(
    learner: Learner,
    retrieval_kit: RetrievalKit,
    treasure_map: TreasureMap,
    delegator_card: DelegatorCard,
    recipient_card: RecipientCard,
    context: Optional[Context] = None,
) -> Dict[IdentityAddress, VerifiedCapsuleFrag]:
    responses: Dict[IdentityAddress, VerifiedCapsuleFrag] = {}

    async def reencrypt(nursery: trio.Nursery, node: VerifiedUrsulaInfo) -> None:
        verified_cfrags = await learner.reencrypt(
            ursula=node,
            capsules=[retrieval_kit.capsule],
            treasure_map=treasure_map,
            delegator_card=delegator_card,
            recipient_card=recipient_card,
            conditions=retrieval_kit.conditions,
            context=context,
        )
        responses[node.staking_provider_address] = verified_cfrags[0]
        if len(responses) == treasure_map.threshold:
            nursery.cancel_scope.cancel()

    destinations = {
        IdentityAddress(bytes(address)): ekfrag
        for address, ekfrag in treasure_map.destinations.items()
    }
    async with trio.open_nursery() as nursery:
        async with verified_nodes_iter(learner, destinations) as node_iter:
            async for node in node_iter:
                nursery.start_soon(reencrypt, nursery, node)
    return responses


async def retrieve_via_learner(
    learner: Learner,
    retrieval_states: List[RetrievalState],
    treasure_map: TreasureMap,
    delegator_card: DelegatorCard,
    recipient_card: RecipientCard,
    context: Optional[Context] = None,
) -> List[RetrievalState]:
    # TODO: the simlpest implementation
    # Need to use batch reencryptions, and not query the Ursulas that have already been queried.
    new_states = []
    for state in retrieval_states:
        vcfrags = await retrieve(
            learner=learner,
            retrieval_kit=state.retrieval_kit,
            treasure_map=treasure_map,
            delegator_card=delegator_card,
            recipient_card=recipient_card,
            context=context,
        )
        new_states.append(state.with_vcfrags(vcfrags))
    return new_states


async def retrieve_via_porter(
    porter_client: PorterClient,
    retrieval_states: List[RetrievalState],
    treasure_map: TreasureMap,
    delegator_card: DelegatorCard,
    recipient_card: RecipientCard,
    context: Optional[Context] = None,
) -> List[RetrievalState]:
    retrieval_kits = [state.retrieval_kit for state in retrieval_states]
    response = await porter_client.retrieve_cfrags(
        treasure_map=treasure_map,
        retrieval_kits=retrieval_kits,
        delegator_card=delegator_card,
        recipient_card=recipient_card,
        context=context,
    )

    return [
        old_state.with_vcfrags(vcfrags) for old_state, vcfrags in zip(retrieval_states, response)
    ]


async def retrieve_and_decrypt(
    client: Union[Learner, PorterClient],
    message_kits: Iterable[MessageKit],
    enacted_policy: EnactedPolicy,
    delegator_card: DelegatorCard,
    recipient: Recipient,
    publisher_card: PublisherCard,
    context: Optional[Context] = None,
) -> List[bytes]:
    treasure_map = recipient.decrypt_treasure_map(
        enacted_policy.encrypted_treasure_map, publisher_card
    )

    retrieval_states = [
        RetrievalState.from_message_kit(message_kit) for message_kit in message_kits
    ]

    # TODO: run mutliple rounds until completion
    if isinstance(client, Learner):
        retrieval_states = await retrieve_via_learner(
            learner=client,
            retrieval_states=retrieval_states,
            treasure_map=treasure_map,
            delegator_card=delegator_card,
            recipient_card=recipient.card(),
            context=context,
        )
    else:
        retrieval_states = await retrieve_via_porter(
            porter_client=client,
            retrieval_states=retrieval_states,
            treasure_map=treasure_map,
            delegator_card=delegator_card,
            recipient_card=recipient.card(),
            context=context,
        )

    # TODO: check that we have enough vcfrags

    decrypted = [
        recipient.decrypt_message_kit(
            message_kit=message_kit, treasure_map=treasure_map, vcfrags=state.vcfrags.values()
        )
        for state, message_kit in zip(retrieval_states, message_kits)
    ]

    return decrypted
