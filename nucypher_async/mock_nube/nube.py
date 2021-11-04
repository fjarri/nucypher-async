import os
from typing import Sequence, Tuple, List


class KeyMaker:

    @classmethod
    def random(cls):
        identity = os.urandom(8).hex()
        return cls(identity)

    def __init__(self, identity):
        self._identity = identity

    def __eq__(self, other):
        return isinstance(other, KeyMaker) and other._identity == self._identity

    def verifying_key(self) -> 'KeyMakerVerifyingKey':
        return KeyMakerVerifyingKey(self)

    def encryption_key(self) -> 'EncryptionKey':
        return EncryptionKey(self)

    def make_key_sliver(self, label: str, recipient_pk: 'RecipientPublicKey', threshold: int, shares: int) -> 'KeySliver':
        return KeySliver(self, label, recipient_pk, threshold, shares)

    def make_key_bits(self, label: str, recipient_pk: 'RecipientPublicKey', threshold: int, shares: int) -> List['KeyBit']:
        return [KeyBit(self, label, recipient_pk, threshold) for _ in range(shares)]


# Basically a single share of a key sliver
class KeyBit:

    def __init__(self, keymaker: KeyMaker, label: str, recipient_pk: 'RecipientPublicKey', threshold: int):
        self._created_by = keymaker
        self._label = label
        self._recipient_pk = recipient_pk
        self._threshold = threshold


class KeySliver:

    def __init__(self, keymaker: KeyMaker, label: str, recipient_pk: 'RecipientPublicKey', threshold: int, shares: int):
        self._created_by = keymaker
        self._label = label
        self._recipient_pk = recipient_pk
        self._threshold = threshold
        self._shares = shares


class KeyMakerVerifyingKey:

    def __init__(self, keymaker: KeyMaker):
        self._created_by = keymaker


class EncryptionKey:

    def __init__(self, keymaker: KeyMaker):
        self._created_by = keymaker

    def verify(self, verifying_key: KeyMakerVerifyingKey) -> 'VerifiedEncryptionKey':
        assert self._created_by == verifying_key._created_by
        return VerifiedEncryptionKey([self._created_by])


class VerifiedEncryptionKey:

    def __init__(self, keymakers: Sequence[KeyMaker]):
        self._created_by = keymakers

    def __add__(self, other):
        assert isinstance(other, VerifiedEncryptionKey)
        return VerifiedEncryptionKey(self._created_by + other._created_by)


class Capsule:

    def __init__(self, encryption_key: VerifiedEncryptionKey):
        self._encryption_key = encryption_key


class Ciphertext:

    def __init__(self, capsule: Capsule, plaintext: str):
        self._capsule = capsule
        self._plaintext = plaintext


def encrypt(encryption_key: VerifiedEncryptionKey, plaintext: str) -> Tuple[Capsule, Ciphertext]:
    capsule = Capsule(encryption_key)
    return capsule, Ciphertext(capsule, plaintext)


class RecipientSecretKey:

    @classmethod
    def random(cls):
        identity = os.urandom(8).hex()
        return cls(identity)

    def __init__(self, identity):
        self._identity = identity

    def public_key(self) -> 'RecipientPublicKey':
        return RecipientPublicKey(self)


class RecipientPublicKey:

    def __init__(self, secret_key: RecipientSecretKey):
        self._secret_key = secret_key


class KeyFrag:

    @classmethod
    def from_bits(cls, key_bits: Sequence[KeyBit]):
        # TODO: check that all the bits are consistent
        return cls(
            created_by=[key_bit._created_by for key_bit in key_bits],
            recipient_pk=key_bits[0]._recipient_pk,
            threshold=key_bits[0]._threshold)

    @classmethod
    def from_slivers(cls, key_slivers: Sequence[KeySliver]):
        # TODO: check that all the slivers are consistent
        return cls(
            created_by=[key_sliver._created_by for key_sliver in key_slivers],
            recipient_pk=key_slivers[0]._recipient_pk,
            threshold=key_slivers[0]._threshold)

    def __init__(self, created_by: List[KeyMaker], recipient_pk: RecipientPublicKey, threshold: int):
        self._created_by = created_by
        self._recipient_pk = recipient_pk
        self._threshold = threshold


def generate_kfrags(kslivers: Sequence[KeySliver]) -> List[KeyFrag]:
    return [KeyFrag.from_slivers(kslivers) for _ in range(kslivers[0]._shares)]


class CapsuleFrag:

    def __init__(self, capsule: Capsule, kfrag: KeyFrag):

        # Sanity check
        assert capsule._encryption_key._created_by == kfrag._created_by

        self._capsule = capsule
        self._kfrag = kfrag

    def verify(self, keymaker_vks: Sequence[KeyMakerVerifyingKey]) -> 'VerifiedCapsuleFrag':
        assert len(keymaker_vks) == len(self._kfrag._created_by)
        assert [vk._created_by for vk in keymaker_vks] == self._kfrag._created_by

        return VerifiedCapsuleFrag(self)


class VerifiedCapsuleFrag:

    def __init__(self, cfrag: CapsuleFrag):
        self._cfrag = cfrag


def reencrypt(capsule: Capsule, kfrag: KeyFrag) -> CapsuleFrag:
    return CapsuleFrag(capsule, kfrag)


def decrypt(recipient_sk: RecipientSecretKey, vcfrags: Sequence[VerifiedCapsuleFrag], ciphertext: Ciphertext) -> str:
    cfrags = [vcfrag._cfrag for vcfrag in vcfrags]
    assert len(cfrags) == cfrags[0]._kfrag._threshold

    for cfrag in cfrags:
        assert cfrag._capsule == ciphertext._capsule
        assert cfrag._kfrag._recipient_pk._secret_key == recipient_sk

    return ciphertext._plaintext
