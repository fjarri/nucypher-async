from collections.abc import Sequence

import trio
from nucypher_core import SessionStaticSecret, ThresholdDecryptionRequest, ThresholdMessageKit
from nucypher_core.ferveo import (
    DecryptionShareSimple,
    FerveoVariant,
    combine_decryption_shares_simple,
)
from pons import AccountSigner

from ..drivers.cbd import CBDAddress, CBDClient, OnChainRitual
from ..drivers.identity import IdentityAddress
from ..p2p.verification import VerifiedNodeInfo
from .network import NetworkClient


async def initiate_ritual(
    network_client: NetworkClient,
    cbd_client: CBDClient,
    shares: int,
    duration: int = 60 * 60 * 24,  # 24 hours
) -> OnChainRitual:
    nodes = await network_client.get_nodes(quantity=shares)

    # TODO: this should be the ritual initiator character
    signer = AccountSigner.create()

    # TODO: add fee models
    fee_model = CBDAddress(b"0" * 20)

    # TODO: figure out who can this be
    authority = IdentityAddress(b"0" * 20)

    providers = [node.staking_provider_address for node in nodes]

    # TODO: who is that? Or is it a contract?
    access_controller = IdentityAddress(b"0" * 20)

    async with cbd_client.session() as session:
        ritual_id = await session.initiate_ritual(
            signer, fee_model, providers, authority, duration, access_controller
        )
        return await session.get_ritual(ritual_id)


async def cbd_decrypt(
    network_client: NetworkClient, cbd_client: CBDClient, message_kit: ThresholdMessageKit
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
        network_client,
        decryption_request=decryption_request,
        participants=participants,
        threshold=ritual.threshold,
    )

    shared_secret = combine_decryption_shares_simple(decryption_shares)

    return message_kit.decrypt_with_shared_secret(shared_secret)


async def get_decryption_shares(
    network_client: NetworkClient,
    decryption_request: ThresholdDecryptionRequest,
    participants: Sequence[OnChainRitual.Participant],
    threshold: int,
) -> list[DecryptionShareSimple]:
    # Currently only the simple variant is supported in the reference
    assert decryption_request.variant == FerveoVariant.Simple

    # use ephemeral key for request
    requester_sk = SessionStaticSecret.random()

    shares = {}

    participants_map = {p.provider: p.decryption_request_static_key for p in participants}

    async def get_share(nursery: trio.Nursery, node: VerifiedNodeInfo) -> None:
        pk = participants_map[node.staking_provider_address]
        shared_secret = requester_sk.derive_shared_secret(pk)
        encrypted_decryption_request = decryption_request.encrypt(
            shared_secret=shared_secret,
            requester_public_key=pk,
        )

        # TODO: get rid of direct `learner` usage
        encrypted_decryption_response = await network_client._learner.decrypt(  # noqa: SLF001
            node, encrypted_decryption_request
        )
        decryption_response = encrypted_decryption_response.decrypt(shared_secret=shared_secret)

        share = DecryptionShareSimple.from_bytes(decryption_response.decryption_share)

        shares[node.staking_provider_address] = share

        if len(shares) == threshold:
            nursery.cancel_scope.cancel()

    async with trio.open_nursery() as nursery:
        async for node_info in network_client.verified_nodes_iter(participants_map):
            nursery.start_soon(get_share, nursery, node_info)

    return list(shares.values())
