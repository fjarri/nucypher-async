import trio

from nucypher_core import TreasureMap, MessageKit, HRAC, ReencryptionRequest, ReencryptionResponse
from nucypher_core.umbral import SecretKeyFactory, Signer, SecretKey, generate_kfrags

class Policy:

    def __init__(self, encrypted_treasure_map, encrypting_key):
        self.encrypted_treasure_map = encrypted_treasure_map
        self.encrypting_key = encrypting_key


class Alice:

    def __init__(self):
        self._skf = SecretKeyFactory.random()
        self._signer = Signer(SecretKey.random())
        self.verifying_key = self._signer.verifying_key()

    async def grant(self, learner, bob, label, threshold, shares, handpicked_addresses=None):

        # TODO: sample Ursulas from the blockchain here

        policy_sk = self._skf.make_key(label)

        kfrags = generate_kfrags(
            delegating_sk=policy_sk,
            receiving_pk=bob.public_key,
            signer=self._signer,
            threshold=threshold,
            shares=shares,
            sign_delegating_key=True,
            sign_receiving_key=True)

        assigned_kfrags = {}
        async with learner.verified_nodes_iter(handpicked_addresses) as aiter:
            async for node in aiter:
                assigned_kfrags[node.metadata.payload.staker_address] = (node.metadata.payload.encrypting_key, kfrags.pop())
                if len(assigned_kfrags) == shares:
                    break

        hrac = HRAC(
            publisher_verifying_key=self.verifying_key,
            bob_verifying_key=bob.verifying_key,
            label=label)
        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=hrac,
            policy_encrypting_key=policy_sk.public_key(),
            assigned_kfrags=assigned_kfrags,
            threshold=threshold)
        encrypted_treasure_map = treasure_map.encrypt(self._signer, bob.public_key)

        return Policy(
            encrypted_treasure_map=encrypted_treasure_map,
            encrypting_key=policy_sk.public_key())


def encrypt(encrypting_key, message):
    return MessageKit(policy_encrypting_key=encrypting_key, plaintext=message)


class Bob:

    def __init__(self):
        self._decrypting_key = SecretKey.random()
        self._signer = Signer(SecretKey.random())

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
            response = await learner._client.reencrypt(node.ssl_contact, request)
            verified_cfrags = response.verify(capsules=request.capsules,
                                              alice_verifying_key=alice_verifying_key,
                                              ursula_verifying_key=node.metadata.payload.verifying_key,
                                              policy_encrypting_key=treasure_map.policy_encrypting_key,
                                              bob_encrypting_key=self.public_key,
                                              )
            responses.add(verified_cfrags[0])
            if len(responses) == treasure_map.threshold:
                nursery.cancel_scope.cancel()

        destinations = treasure_map.destinations
        async with trio.open_nursery() as nursery:
            async with learner.verified_nodes_iter(destinations) as aiter:
                async for node in aiter:
                    nursery.start_soon(reencrypt, nursery, node, destinations[node.metadata.payload.staker_address])
        return responses

    async def retrieve_and_decrypt(self, learner, message_kit, encrypted_treasure_map, alice_verifying_key):
        vcfrags = await self.retrieve(learner, message_kit.capsule, encrypted_treasure_map, alice_verifying_key)

        publisher_verifying_key = alice_verifying_key
        treasure_map = encrypted_treasure_map.decrypt(self._decrypting_key, publisher_verifying_key)

        return message_kit.decrypt_reencrypted(self._decrypting_key,
            treasure_map.policy_encrypting_key,
            list(vcfrags))
