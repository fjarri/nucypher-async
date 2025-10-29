from typing import Dict, List, Sequence, cast

import trio
from nucypher_core import SessionStaticSecret, ThresholdDecryptionRequest, ThresholdMessageKit
from nucypher_core.ferveo import (
    DecryptionShareSimple,
    FerveoVariant,
    SharedSecret,
    combine_decryption_shares_simple,
)

from ..drivers.cbd import CBDClient, Ritual
from ..p2p.algorithms import get_ursulas, verified_nodes_iter
from ..p2p.learner import Learner
from ..p2p.verification import VerifiedUrsulaInfo


async def initiate_ritual(
    learner: Learner,
    cbd_client: CBDClient,
    shares: int,
) -> Ritual:
    nodes = await get_ursulas(learner=learner, quantity=shares)

    async with cbd_client.session() as session:
        ritual_id = await session.initiate_ritual()
        ritual = await session.get_ritual(ritual_id)

    return ritual


async def cbd_decrypt(
    learner: Learner, cbd_client: CBDClient, message_kit: ThresholdMessageKit
) -> bytes:
    async with cbd_client.session() as session:
        ritual_id = await session.get_ritual_id_from_public_key(message_kit.acp.public_key)
        ritual = await session.get_ritual(ritual_id)
        participants = await session.get_participants(ritual_id)

    decryption_request = ThresholdDecryptionRequest(
        ritual_id=ritual_id,
        variant=FerveoVariant.Simple,
        ciphertext_header=message_kit.ciphertext_header,
        acp=message_kit.acp,
        context=None,  # CHECK: what is this?
    )

    decryption_shares = await get_decryption_shares(
        learner=learner,
        decryption_request=decryption_request,
        participants=participants,
        threshold=ritual.threshold,
    )

    shared_secret = combine_decryption_shares_simple(decryption_shares)

    return message_kit.decrypt_with_shared_secret(shared_secret)


async def get_decryption_shares(
    learner: Learner,
    decryption_request: ThresholdDecryptionRequest,
    participants: Sequence[Ritual.Participant],
    threshold: int,
) -> List[DecryptionShareSimple]:
    # TODO: add support for FerveoVariant.Precomputed
    # Using just Simple for now to avoid typing issues,
    # and it's hardcoded in the caller anyway.
    assert decryption_request.variant == FerveoVariant.Simple

    # use ephemeral key for request
    requester_sk = SessionStaticSecret.random()
    requester_public_key = requester_sk.public_key()

    shares = {}

    participants_map = {p.provider: p.decryption_request_static_key for p in participants}

    async def get_share(nursery: trio.Nursery, node: VerifiedUrsulaInfo) -> None:
        pk = participants_map[node.staking_provider_address]
        shared_secret = requester_sk.derive_shared_secret(pk)
        encrypted_decryption_request = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=pk,
        )

        encrypted_decryption_response = await learner.decrypt(node, encrypted_decryption_request)
        decryption_response = encrypted_decryption_response.decrypt(shared_secret=shared_secret)

        share = DecryptionShareSimple.from_bytes(decryption_response.decryption_share)

        shares[node.staking_provider_address] = share

        if len(shares) == threshold:
            nursery.cancel_scope.cancel()

    async with trio.open_nursery() as nursery:
        async with verified_nodes_iter(learner, participants_map) as node_iter:
            async for node in node_iter:
                nursery.start_soon(get_share, nursery, node)

    return list(shares.values())
