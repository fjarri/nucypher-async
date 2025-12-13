import os
from dataclasses import dataclass

from nucypher_async.blockchain.identity import IdentityAddress
from nucypher_async.characters import MasterKey
from nucypher_async.characters.pre import (
    DecryptionKit,
    Delegator,
    EncryptedMessage,
    Publisher,
    Recipient,
    Reencryptor,
)


@dataclass
class Node:
    # This would normally be the staking provider address,
    # but for this test it only matters that it uniquely identifies the node.
    identity: IdentityAddress
    reencryptor: Reencryptor


def test_grant_and_retrieve() -> None:
    bob = Recipient(MasterKey.random())
    alice = Delegator(MasterKey.random())
    publisher = Publisher(MasterKey.random())

    nodes = [
        Node(
            identity=IdentityAddress(os.urandom(20)),
            reencryptor=Reencryptor(MasterKey.random()),
        )
        for _ in range(3)
    ]

    # Alice grants to Bob

    policy = alice.make_policy(
        recipient_card=bob.card(),
        label=b"some label",
        threshold=2,
        shares=3,
    )

    # Publisher distributes fragments

    assigned_kfrags = {
        node.identity: (node.reencryptor.card(), key_frag)
        for node, key_frag in zip(nodes, policy.key_frags, strict=True)
    }

    # This is published along with the policy details

    encrypted_treasure_map = publisher.make_treasure_map(
        policy=policy, recipient_card=bob.card(), assigned_kfrags=assigned_kfrags
    )

    # Someone encrypts a message

    message = b"a secret message"
    encrypted_message = EncryptedMessage(policy, message)

    # Bob decrypts

    treasure_map = bob.decrypt_treasure_map(encrypted_treasure_map, publisher.card())
    decryption_kit = DecryptionKit(encrypted_message, treasure_map)
    vcfrags = []

    for node in nodes:
        # Bob gets this out of the treasure map and sends it to the node, along with the capsule
        ekfrag_sent = decryption_kit.encrypted_kfrags[node.identity]
        capsule_sent = decryption_kit.capsule

        # The node reencrypts
        vkfrag = node.reencryptor.decrypt_kfrag(
            encrypted_kfrag=ekfrag_sent,
            hrac=policy.hrac,
            publisher_card=publisher.card(),
        )
        vcfrag = node.reencryptor.reencrypt(verified_kfrag=vkfrag, capsules=[capsule_sent])[0]

        # `vcfrag` is sent in the response to Bob
        vcfrags.append(vcfrag)

    # `threshold` cfrags is enough to decrypt
    decrypted = bob.decrypt(
        decryption_kit=decryption_kit,
        vcfrags=vcfrags[: policy.threshold],
    )

    assert message == decrypted
