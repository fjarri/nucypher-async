from typing import NamedTuple

import arrow
import trio

from nucypher_core import (
    TreasureMap, MessageKit, HRAC, ReencryptionRequest, ReencryptionResponse,
    EncryptedTreasureMap
    )
from nucypher_core.umbral import SecretKeyFactory, Signer, SecretKey, generate_kfrags, PublicKey

from .drivers.identity import IdentityAddress
from .drivers.payment import PaymentAccount, PaymentAccountSigner
from .master_key import MasterKey


class Policy(NamedTuple):
    encrypted_treasure_map: EncryptedTreasureMap
    encrypting_key: PublicKey
    start: int
    end: int


class Alice:

    def __init__(self, payment_account=None):
        self.__master_key = MasterKey.random()
        self._signer = self.__master_key.make_signer()
        self.verifying_key = self._signer.verifying_key()
        self._delegating_skf = self.__master_key.make_delegating_key_factory()
        if payment_account is None:
            payment_account = PaymentAccount.random()
        self._payment_account = payment_account

    @property
    def payment_address(self):
        return self._payment_account.address

    def public_info(self):
        return RemoteAlice(verifying_key=self.verifying_key)

    async def grant(self, learner, payment_client, bob, label, threshold, shares, handpicked_addresses=None):

        # TODO: sample Ursulas from the blockchain here

        policy_sk = self._delegating_skf.make_key(label)

        hrac = HRAC(
            publisher_verifying_key=self.verifying_key,
            bob_verifying_key=bob.verifying_key,
            label=label)

        async with payment_client.session() as session:
            if await session.is_policy_active(hrac):
                raise RuntimeError(f"Policy {hrac} is already active")

        kfrags = generate_kfrags(
            delegating_sk=policy_sk,
            receiving_pk=bob.encrypting_key,
            signer=self._signer,
            threshold=threshold,
            shares=shares,
            sign_delegating_key=True,
            sign_receiving_key=True)

        handpicked_addresses = handpicked_addresses or set()
        nodes = []
        async with learner.verified_nodes_iter(handpicked_addresses) as aiter:
            async for node in aiter:
                nodes.append(node)

        if len(nodes) < shares:
            # TODO: implement ranking for granting, don't just pick random nodes
            async with learner.random_verified_nodes_iter(shares - len(nodes), exclude=handpicked_addresses) as aiter:
                async for node in aiter:
                    nodes.append(node)

        assigned_kfrags = {
            bytes(node.staking_provider_address): (node.metadata.payload.encrypting_key, kfrags.pop())
            for node in nodes}

        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=hrac,
            policy_encrypting_key=policy_sk.public_key(),
            assigned_kfrags=assigned_kfrags,
            threshold=threshold)
        encrypted_treasure_map = treasure_map.encrypt(self._signer, bob.encrypting_key)

        policy_start = learner._clock.utcnow()
        policy_end = policy_start.shift(days=30) # TODO: make adjustable

        signer = PaymentAccountSigner(self._payment_account)
        async with payment_client.session() as session:
            await session.create_policy(
                signer, hrac, shares, int(policy_start.timestamp()), int(policy_end.timestamp()))

        return Policy(
            start=policy_start,
            end=policy_end,
            encrypted_treasure_map=encrypted_treasure_map,
            encrypting_key=policy_sk.public_key())


class RemoteAlice:

    def __init__(self, verifying_key):
        self.verifying_key = verifying_key


def encrypt(encrypting_key, message):
    return MessageKit(policy_encrypting_key=encrypting_key, plaintext=message)


class Bob:

    def __init__(self):
        self.__master_key = MasterKey.random()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self._signer = self.__master_key.make_signer()

        self.encrypting_key = self._decrypting_key.public_key()
        self.verifying_key = self._signer.verifying_key()

    def public_info(self):
        return RemoteBob(
            encrypting_key=self.encrypting_key,
            verifying_key=self.verifying_key)

    async def retrieve(self, learner, capsule, encrypted_treasure_map, alice_verifying_key):

        publisher_verifying_key = alice_verifying_key
        treasure_map = encrypted_treasure_map.decrypt(self._decrypting_key, publisher_verifying_key)

        responses = set()

        async def reencrypt(nursery, node, ekfrag):
            request = ReencryptionRequest(
                capsules=[capsule],
                hrac=treasure_map.hrac,
                encrypted_kfrag=ekfrag,
                publisher_verifying_key=treasure_map.publisher_verifying_key,
                bob_verifying_key=self.verifying_key)
            # TODO: why are we calling a private method here?
            response = await learner._peer_client.reencrypt(node.secure_contact, request)
            verified_cfrags = response.verify(capsules=request.capsules,
                                              alice_verifying_key=alice_verifying_key,
                                              ursula_verifying_key=node.metadata.payload.verifying_key,
                                              policy_encrypting_key=treasure_map.policy_encrypting_key,
                                              bob_encrypting_key=self.encrypting_key,
                                              )
            responses.add(verified_cfrags[0])
            if len(responses) == treasure_map.threshold:
                nursery.cancel_scope.cancel()

        destinations = {IdentityAddress(address): ekfrag for address, ekfrag in treasure_map.destinations.items()}
        async with trio.open_nursery() as nursery:
            async with learner.verified_nodes_iter(destinations) as aiter:
                async for node in aiter:
                    nursery.start_soon(reencrypt, nursery, node, destinations[node.staking_provider_address])
        return responses

    async def retrieve_and_decrypt(self, learner, message_kit, encrypted_treasure_map, remote_alice):
        vcfrags = await self.retrieve(learner, message_kit.capsule, encrypted_treasure_map, remote_alice.verifying_key)

        publisher_verifying_key = remote_alice.verifying_key
        treasure_map = encrypted_treasure_map.decrypt(self._decrypting_key, publisher_verifying_key)

        return message_kit.decrypt_reencrypted(self._decrypting_key,
            treasure_map.policy_encrypting_key,
            list(vcfrags))


class RemoteBob:

    def __init__(self, encrypting_key, verifying_key):
        self.encrypting_key = encrypting_key
        self.verifying_key = verifying_key
