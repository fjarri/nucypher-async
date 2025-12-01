from abc import ABC, abstractmethod

import arrow
import trio
from attrs import frozen
from nucypher_core import Context, EncryptedTreasureMap, TreasureMap
from nucypher_core.umbral import PublicKey, VerifiedCapsuleFrag

from ..characters.pre import (
    DecryptionKit,
    DelegatorCard,
    MessageKit,
    Policy,
    Publisher,
    PublisherCard,
    Recipient,
    RecipientCard,
    RetrievalKit,
)
from ..drivers.identity import IdentityAddress
from ..drivers.pre import PREAccountSigner, PREClient
from ..p2p.verification import VerifiedNodeInfo
from .network import NetworkClient


@frozen
class EnactedPolicy:
    policy: Policy
    encrypted_treasure_map: EncryptedTreasureMap
    encrypting_key: PublicKey
    start: arrow.Arrow
    end: arrow.Arrow


@frozen
class PRERetrievalOutcome:
    # TODO: merge the two fields into dict[IdentityAddress, VerifiedCapsuleFrag | Exception]?
    cfrags: dict[IdentityAddress, VerifiedCapsuleFrag]
    errors: dict[IdentityAddress, str]


class BasePREConsumerClient(ABC):
    @abstractmethod
    async def retrieve(
        self,
        treasure_map: TreasureMap,
        message_kit: MessageKit | RetrievalKit,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        context: Context | None = None,
    ) -> PRERetrievalOutcome: ...

    async def decrypt(
        self,
        recipient: Recipient,
        enacted_policy: EnactedPolicy,
        message_kit: MessageKit,
        delegator_card: DelegatorCard,
        publisher_card: PublisherCard | None = None,
        context: Context | None = None,
    ) -> bytes:
        treasure_map = recipient.decrypt_treasure_map(
            enacted_policy.encrypted_treasure_map, publisher_card or delegator_card
        )

        # TODO: run mutliple rounds until completion
        outcome = await self.retrieve(
            treasure_map=treasure_map,
            message_kit=message_kit,
            delegator_card=delegator_card,
            recipient_card=recipient.card(),
            context=context,
        )

        # TODO: check that we have enough vcfrags
        return recipient.decrypt(
            decryption_kit=DecryptionKit(message_kit, treasure_map),
            vcfrags=outcome.cfrags.values(),
        )


def pre_encrypt(policy: Policy | EnactedPolicy, message: bytes) -> MessageKit:
    policy_ = policy.policy if isinstance(policy, EnactedPolicy) else policy
    return MessageKit(policy_, message, conditions=None)


class LocalPREClient(BasePREConsumerClient):
    def __init__(self, network_client: NetworkClient, pre_client: PREClient):
        self._network_client = network_client
        self._pre_client = pre_client

    async def retrieve(
        self,
        treasure_map: TreasureMap,
        message_kit: MessageKit | RetrievalKit,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        context: Context | None = None,
    ) -> PRERetrievalOutcome:
        responses: dict[IdentityAddress, VerifiedCapsuleFrag] = {}

        async def reencrypt(nursery: trio.Nursery, node_info: VerifiedNodeInfo) -> None:
            verified_cfrags = await self._network_client.node_client.reencrypt(
                node_info=node_info,
                # TODO: support retrieving for several capsules at once - REST API allows it
                capsules=[message_kit.capsule],
                treasure_map=treasure_map,
                delegator_card=delegator_card,
                recipient_card=recipient_card,
                conditions=message_kit.conditions,
                context=context,
            )
            responses[node_info.staking_provider_address] = verified_cfrags[0]
            if len(responses) == treasure_map.threshold:
                nursery.cancel_scope.cancel()

        destinations = {
            IdentityAddress(bytes(address)): ekfrag
            for address, ekfrag in treasure_map.destinations.items()
        }
        async with trio.open_nursery() as nursery:
            async for node_info in self._network_client.verified_nodes_iter(destinations):
                nursery.start_soon(reencrypt, nursery, node_info)
        return PRERetrievalOutcome(cfrags=responses, errors={})

    async def grant(
        self,
        publisher: Publisher,
        signer: PREAccountSigner,
        policy: Policy,
        recipient_card: RecipientCard,
    ) -> EnactedPolicy:
        async with self._pre_client.session() as session:
            if await session.is_policy_active(policy.hrac):
                raise RuntimeError(f"Policy {policy.hrac} is already active")

        shares = len(policy.key_frags)

        nodes = await self._network_client.get_nodes(shares)

        assigned_kfrags = {
            node.staking_provider_address: (node.reencryptor_card(), key_frag)
            for node, key_frag in zip(nodes, policy.key_frags, strict=True)
        }

        encrypted_treasure_map = publisher.make_treasure_map(
            policy=policy, recipient_card=recipient_card, assigned_kfrags=assigned_kfrags
        )

        policy_start = self._network_client.clock.utcnow()
        policy_end = policy_start.shift(days=30)  # TODO: make adjustable

        async with self._pre_client.session() as session:
            await session.create_policy(
                signer,
                policy.hrac,
                shares,
                int(policy_start.timestamp()),
                int(policy_end.timestamp()),
            )

        return EnactedPolicy(
            policy=policy,
            start=policy_start,
            end=policy_end,
            encrypted_treasure_map=encrypted_treasure_map,
            encrypting_key=policy.encrypting_key,
        )
