from typing import NamedTuple, Dict

import trio

from .mock_nube.nube import *


class Enrico:

    def make_encrypting_key(self, label, keymaker_servers):

        # obtained earlier
        keymaker_vks = [keymaker_server.keymaker.verifying_key() for keymaker_server in keymaker_servers]


        key_parts = [keymaker_server.keymaker.encryption_key() for keymaker_server in keymaker_servers]

        # Verifies that they come from the known keymakers
        verified_key_parts = [key_part.verify(vk) for key_part, vk in zip(key_parts, keymaker_vks)]

        # Accumulates the encryption key
        encryption_key = verified_key_parts[0] + verified_key_parts[1] + verified_key_parts[2] + verified_key_parts[3]

        return encryption_key

    def encrypt(self, encryption_key, plaintext):
        capsule, ciphertext = encrypt(encryption_key, plaintext)
        return capsule, ciphertext


class Bob:

    def __init__(self):
        self.secret_key = RecipientSecretKey.random()
        self.public_key = self.secret_key.public_key()

    def purchase(self, blockchain, label, threshold, shares):
        policy = blockchain.purchase(label, self.public_key, threshold, shares)
        return policy

    async def retrieve_cfrags(self, learner, capsule, policy, treasure_maps):
        cfrags = []
        for ursula_id in policy.ursula_ids[:policy.threshold]:
            key_bits = [treasure_map.destinations[ursula_id] for treasure_map in treasure_maps]
            ursula_metadata = learner.nodes[ursula_id]
            cfrag = await learner._client.reencrypt_dkg(ursula_metadata.address, capsule, key_bits)
            cfrags.append(cfrag)
        return cfrags


class MockBlockchain:

    def __init__(self, ursula_servers):
        # All the stakers are known in the blockchain
        self.ursula_servers = ursula_servers

        self.policies = {}

    def purchase(self, label, recipient_pk, threshold, shares):
        # Sample Ursulas
        ursula_ids = [ursula_server.ursula.id for ursula_server in self.ursula_servers[:shares]]

        policy = Policy(ursula_ids, recipient_pk, threshold, shares)

        self.policies[label] = policy

        return policy


class Policy(NamedTuple):

    ursula_ids: List[str]
    recipient_pk: RecipientPublicKey
    threshold: int
    shares: int


class TreasureMap(NamedTuple):
    destinations: Dict[str, KeyBit] # the keyfrag bits will be encrypted for these ursulas


class KeyMakerServer:

    def __init__(self):
        self.keymaker = KeyMaker.random()

    def get_treasure_map(self, blockchain, label):
        policy = blockchain.policies[label]

        bits = self.keymaker.make_key_bits(label, policy.recipient_pk, policy.threshold, policy.shares)

        # Should be encrypted for the Ursulas
        destinations = {ursula_id: bit for ursula_id, bit in zip(policy.ursula_ids, bits)}

        return TreasureMap(destinations)
