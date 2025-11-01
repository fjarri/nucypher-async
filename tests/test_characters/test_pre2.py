import os
from dataclasses import dataclass

from nucypher_core import Address, MessageKit, RetrievalKit

from nucypher_async.characters.pre import Delegator, Publisher, Recipient, Reencryptor
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.drivers.pre import PREAccount
from nucypher_async.master_key import MasterKey


@dataclass
class Node:
    # This would normally be the staking provider address,
    # but for this test it only matters that it uniquely identifies the node.
    identity: IdentityAddress
    reencryptor: Reencryptor


def test_grant_and_retrieve() -> None:
    bob = Recipient(MasterKey.random())
    alice = Delegator(MasterKey.random())
    publisher = Publisher(MasterKey.random(), PREAccount.random())

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
    message_kit = MessageKit(
        policy_encrypting_key=policy.encrypting_key, plaintext=message, conditions=None
    )

    # Bob decrypts

    treasure_map = bob.decrypt_treasure_map(encrypted_treasure_map, publisher.card())
    retrieval_kit = RetrievalKit.from_message_kit(message_kit)
    vcfrags = []

    for node in nodes:
        # Bob gets this out of the treasure map and sends it to the node
        ekfrag = treasure_map.destinations[Address(bytes(node.identity))]

        # The node reencrypts
        vkfrag = node.reencryptor.decrypt_kfrag(
            encrypted_kfrag=ekfrag,
            hrac=policy.hrac,
            publisher_card=publisher.card(),
        )
        vcfrag = node.reencryptor.reencrypt(
            verified_kfrag=vkfrag, capsules=[retrieval_kit.capsule]
        )[0]

        # `vcfrag` is sent in the response to Bob
        vcfrags.append(vcfrag)

    # `threshold` cfrags is enough to decrypt
    decrypted = bob.decrypt_message_kit(
        message_kit=message_kit,
        treasure_map=treasure_map,
        vcfrags=vcfrags[: policy.threshold],
    )

    assert message == decrypted
