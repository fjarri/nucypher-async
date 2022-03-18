from typing import NamedTuple

import trio

from nucypher_core import (
    TreasureMap, MessageKit, HRAC, ReencryptionRequest, ReencryptionResponse,
    EncryptedTreasureMap
    )
from nucypher_core.umbral import SecretKeyFactory, Signer, SecretKey, generate_kfrags, PublicKey

from .drivers.identity import IdentityAddress
from .drivers.payment import PaymentAccount
from .master_key import MasterKey


class Policy(NamedTuple):
    encrypted_treasure_map: EncryptedTreasureMap
    encrypting_key: PublicKey
    start: int
    end: int


class Alice:

    def __init__(self):
        self.__master_key = MasterKey.random()
        self._signer = self.__master_key.make_signer()
        self.verifying_key = self._signer.verifying_key()
        self._delegating_skf = self.__master_key.make_delegating_key_factory()
        self._payment_account = PaymentAccount.random()

    @property
    def payment_address(self):
        return self._payment_account.address

    async def grant(self, learner, payment_client, bob, label, threshold, shares, handpicked_addresses=None):

        # TODO: sample Ursulas from the blockchain here

        policy_sk = self._delegating_skf.make_key(label)

        hrac = HRAC(
            publisher_verifying_key=self.verifying_key,
            bob_verifying_key=bob.verifying_key,
            label=label)

        if await payment_client.is_policy_active(hrac):
            raise RuntimeError(f"Policy {hrac} is already active")

        kfrags = generate_kfrags(
            delegating_sk=policy_sk,
            receiving_pk=bob.public_key,
            signer=self._signer,
            threshold=threshold,
            shares=shares,
            sign_delegating_key=True,
            sign_receiving_key=True)

        # TODO: pick Ursulas at random
        assigned_kfrags = {}
        async with learner.verified_nodes_iter(handpicked_addresses) as aiter:
            async for node in aiter:
                assigned_kfrags[bytes(node.staking_provider_address)] = (node.metadata.payload.encrypting_key, kfrags.pop())
                if len(assigned_kfrags) == shares:
                    break

        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=hrac,
            policy_encrypting_key=policy_sk.public_key(),
            assigned_kfrags=assigned_kfrags,
            threshold=threshold)
        encrypted_treasure_map = treasure_map.encrypt(self._signer, bob.public_key)

        policy_start = int(trio.current_time())
        policy_end = policy_start + 60 * 60 * 24 * 30 # TODO: make adjustable

        signing_payment_client = payment_client.with_signer(self._payment_account)
        await signing_payment_client.create_policy(hrac, shares, policy_start, policy_end)

        return Policy(
            start=policy_start,
            end=policy_end,
            encrypted_treasure_map=encrypted_treasure_map,
            encrypting_key=policy_sk.public_key())


def encrypt(encrypting_key, message):
    return MessageKit(policy_encrypting_key=encrypting_key, plaintext=message)


class Bob:

    def __init__(self):
        self.__master_key = MasterKey.random()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self._signer = self.__master_key.make_signer()

        self.public_key = self._decrypting_key.public_key()
        self.verifying_key = self._signer.verifying_key()

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
            response = await learner._rest_client.reencrypt(node.ssl_contact, request)
            verified_cfrags = response.verify(capsules=request.capsules,
                                              alice_verifying_key=alice_verifying_key,
                                              ursula_verifying_key=node.metadata.payload.verifying_key,
                                              policy_encrypting_key=treasure_map.policy_encrypting_key,
                                              bob_encrypting_key=self.public_key,
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

    async def retrieve_and_decrypt(self, learner, message_kit, encrypted_treasure_map, alice_verifying_key):
        vcfrags = await self.retrieve(learner, message_kit.capsule, encrypted_treasure_map, alice_verifying_key)

        publisher_verifying_key = alice_verifying_key
        treasure_map = encrypted_treasure_map.decrypt(self._decrypting_key, publisher_verifying_key)

        return message_kit.decrypt_reencrypted(self._decrypting_key,
            treasure_map.policy_encrypting_key,
            list(vcfrags))
