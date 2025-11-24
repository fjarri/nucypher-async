from collections.abc import Iterable, Mapping

from attrs import frozen
from nucypher_core import (
    HRAC,
    Address,
    Conditions,
    EncryptedKeyFrag,
    EncryptedTreasureMap,
    TreasureMap,
)
from nucypher_core import MessageKit as CoreMessageKit
from nucypher_core import RetrievalKit as CoreRetrievalKit
from nucypher_core.umbral import (
    Capsule,
    PublicKey,
    VerifiedCapsuleFrag,
    VerifiedKeyFrag,
    generate_kfrags,
    reencrypt,
)

from ..drivers.identity import IdentityAddress
from ..drivers.peer import PeerPrivateKey
from ..master_key import MasterKey


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


# TODO: rename to `EncryptedMessage` and remove `Encryptor` character?
class MessageKit:
    def __init__(self, policy: Policy, message: bytes, conditions: Conditions | None = None):
        self.core_message_kit = CoreMessageKit(
            policy_encrypting_key=policy.encrypting_key, plaintext=message, conditions=conditions
        )
        self.capsule = self.core_message_kit.capsule
        self.conditions = self.core_message_kit.conditions


# TODO: rename to something like `EncryptedMessageMetadata`?
class RetrievalKit:
    @classmethod
    def from_message_kit(cls, message_kit: MessageKit) -> "RetrievalKit":
        return cls(CoreRetrievalKit.from_message_kit(message_kit.core_message_kit))

    def __init__(self, retrieval_kit: CoreRetrievalKit):
        self.core_retrieval_kit = retrieval_kit
        self.capsule = self.core_retrieval_kit.capsule
        self.conditions = self.core_retrieval_kit.conditions


class Encryptor:
    @staticmethod
    def encrypt(policy: Policy, message: bytes, conditions: Conditions | None = None) -> MessageKit:
        return MessageKit(policy, message, conditions=conditions)


@frozen
class PublisherCard:
    verifying_key: PublicKey


class DecryptionKit:
    encrypted_kfrags: dict[IdentityAddress, EncryptedKeyFrag]

    capsule: Capsule

    def __init__(self, message_kit: MessageKit, treasure_map: TreasureMap):
        self.core_message_kit = message_kit.core_message_kit
        self.core_treasure_map = treasure_map
        self.capsule = self.core_message_kit.capsule
        self.encrypted_kfrags = {
            IdentityAddress(bytes(address)): ekfrag
            for address, ekfrag in self.core_treasure_map.destinations.items()
        }


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
        return decryption_kit.core_message_kit.decrypt_reencrypted(
            self._decrypting_key,
            decryption_kit.core_treasure_map.policy_encrypting_key,
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

    def make_peer_private_key(self) -> PeerPrivateKey:
        return self.__master_key.make_peer_private_key()

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
