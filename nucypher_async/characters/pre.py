from collections.abc import Iterable, Mapping

from attrs import frozen
from nucypher_core import (
    HRAC,
    Address,
    Conditions,
    EncryptedKeyFrag,
    EncryptedTreasureMap,
    MessageKit,
    RetrievalKit,
    TreasureMap,
)
from nucypher_core.umbral import (
    Capsule,
    PublicKey,
    VerifiedCapsuleFrag,
    VerifiedKeyFrag,
    generate_kfrags,
    reencrypt,
)

from ..blockchain.identity import IdentityAddress
from ._master_key import MasterKey


@frozen
class Policy:
    hrac: HRAC
    key_frags: list[VerifiedKeyFrag]
    encrypting_key: PublicKey
    threshold: int


class Delegator:
    @classmethod
    def random(cls) -> "Delegator":
        return cls(MasterKey.random())

    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()
        self._delegating_skf = self.__master_key.make_delegating_key_factory()
        self.verifying_key = self._signer.verifying_key()

    def card(self) -> "DelegatorCard":
        return DelegatorCard(verifying_key=self.verifying_key)

    def make_policy(
        self, recipient_card: "RecipientCard", label: bytes, threshold: int, shares: int
    ) -> Policy:
        policy_sk = self._delegating_skf.make_key(label)

        hrac = HRAC(
            publisher_verifying_key=self.verifying_key,
            bob_verifying_key=recipient_card.verifying_key,
            label=label,
        )

        key_frags = generate_kfrags(
            delegating_sk=policy_sk,
            receiving_pk=recipient_card.encrypting_key,
            signer=self._signer,
            threshold=threshold,
            shares=shares,
            sign_delegating_key=True,
            sign_receiving_key=True,
        )

        return Policy(
            hrac=hrac,
            threshold=threshold,
            key_frags=key_frags,
            encrypting_key=policy_sk.public_key(),
        )


@frozen
class DelegatorCard:
    verifying_key: PublicKey


class Publisher:
    @classmethod
    def random(cls) -> "Publisher":
        return cls(MasterKey.random())

    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()
        self.verifying_key = self._signer.verifying_key()

    def make_treasure_map(
        self,
        policy: Policy,
        recipient_card: "RecipientCard",
        assigned_kfrags: Mapping[IdentityAddress, tuple["ReencryptorCard", VerifiedKeyFrag]],
    ) -> EncryptedTreasureMap:
        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=policy.hrac,
            policy_encrypting_key=policy.encrypting_key,
            assigned_kfrags={
                Address(bytes(address)): (reencryptor.encrypting_key, vkfrag)
                for address, (reencryptor, vkfrag) in assigned_kfrags.items()
            },
            threshold=policy.threshold,
        )
        return treasure_map.encrypt(self._signer, recipient_card.encrypting_key)

    def card(self) -> "PublisherCard":
        return PublisherCard(verifying_key=self.verifying_key)


class EncryptedMessage:
    def __init__(self, policy: Policy, message: bytes, conditions: Conditions | None = None):
        self.message_kit = MessageKit(
            policy_encrypting_key=policy.encrypting_key, plaintext=message, conditions=conditions
        )

    @property
    def capsule(self) -> Capsule:
        return self.message_kit.capsule

    @property
    def conditions(self) -> Conditions | None:
        return self.message_kit.conditions

    @property
    def metadata(self) -> "EncryptedMessageMetadata":
        return EncryptedMessageMetadata(RetrievalKit.from_message_kit(self.message_kit))


class EncryptedMessageMetadata:
    def __init__(self, retrieval_kit: RetrievalKit):
        self.retrieval_kit = retrieval_kit

    @property
    def capsule(self) -> Capsule:
        return self.retrieval_kit.capsule

    @property
    def conditions(self) -> Conditions | None:
        return self.retrieval_kit.conditions


@frozen
class PublisherCard:
    verifying_key: PublicKey


class DecryptionKit:
    encrypted_kfrags: dict[IdentityAddress, EncryptedKeyFrag]

    def __init__(self, encrypted_message: EncryptedMessage, treasure_map: TreasureMap):
        self.message_kit = encrypted_message.message_kit
        self.treasure_map = treasure_map
        self.encrypted_kfrags = {
            IdentityAddress(bytes(address)): ekfrag
            for address, ekfrag in self.treasure_map.destinations.items()
        }

    @property
    def capsule(self) -> Capsule:
        return self.message_kit.capsule


class Recipient:
    @classmethod
    def random(cls) -> "Recipient":
        return cls(MasterKey.random())

    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self._signer = self.__master_key.make_signer()

        self.encrypting_key = self._decrypting_key.public_key()
        self.verifying_key = self._signer.verifying_key()

    def card(self) -> "RecipientCard":
        return RecipientCard(encrypting_key=self.encrypting_key, verifying_key=self.verifying_key)

    def decrypt_treasure_map(
        self, encrypted_tmap: EncryptedTreasureMap, publisher_card: PublisherCard | DelegatorCard
    ) -> TreasureMap:
        verifying_key = publisher_card.verifying_key
        return encrypted_tmap.decrypt(self._decrypting_key, verifying_key)

    def decrypt(
        self,
        decryption_kit: DecryptionKit,
        vcfrags: Iterable[VerifiedCapsuleFrag],
    ) -> bytes:
        return decryption_kit.message_kit.decrypt_reencrypted(
            self._decrypting_key,
            decryption_kit.treasure_map.policy_encrypting_key,
            list(vcfrags),
        )


@frozen
class RecipientCard:
    encrypting_key: PublicKey
    verifying_key: PublicKey


class Reencryptor:
    def __init__(
        self,
        master_key: MasterKey,
    ):
        self.__master_key = master_key
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self.encrypting_key = self._decrypting_key.public_key()

    def decrypt_kfrag(
        self,
        encrypted_kfrag: EncryptedKeyFrag,
        hrac: HRAC,
        publisher_card: PublisherCard,
    ) -> VerifiedKeyFrag:
        return encrypted_kfrag.decrypt(self._decrypting_key, hrac, publisher_card.verifying_key)

    def reencrypt(
        self, verified_kfrag: VerifiedKeyFrag, capsules: Iterable[Capsule]
    ) -> list[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]

    def card(self) -> "ReencryptorCard":
        return ReencryptorCard(encrypting_key=self.encrypting_key)


@frozen
class ReencryptorCard:
    encrypting_key: PublicKey
