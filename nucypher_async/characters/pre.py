from typing import Optional, Iterable, List, Mapping, Tuple

from attrs import frozen

from nucypher_core import (
    Address,
    TreasureMap,
    MessageKit,
    HRAC,
    EncryptedTreasureMap,
    EncryptedKeyFrag,
)
from nucypher_core.umbral import (
    generate_kfrags,
    PublicKey,
    Capsule,
    VerifiedKeyFrag,
    VerifiedCapsuleFrag,
    RecoverableSignature,
    reencrypt,
)

from ..drivers.peer import PeerPrivateKey
from ..drivers.identity import IdentityAccount
from ..drivers.payment import PaymentAccount, PaymentAccountSigner
from ..master_key import MasterKey


@frozen
class Policy:
    hrac: HRAC
    key_frags: List[VerifiedKeyFrag]
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


class DelegatorCard:
    def __init__(self, verifying_key: PublicKey):
        self.verifying_key = verifying_key


class Publisher:
    @classmethod
    def random(cls) -> "Publisher":
        return cls(MasterKey.random(), PaymentAccount.random())

    def __init__(self, master_key: MasterKey, payment_account: PaymentAccount):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()
        self._payment_account = payment_account
        self.payment_signer = PaymentAccountSigner(self._payment_account)
        self.payment_address = self._payment_account.address
        self.verifying_key = self._signer.verifying_key()

    def make_treasure_map(
        self,
        policy: Policy,
        recipient_card: "RecipientCard",
        assigned_kfrags: Mapping[Address, Tuple[PublicKey, VerifiedKeyFrag]],
    ) -> EncryptedTreasureMap:
        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=policy.hrac,
            policy_encrypting_key=policy.encrypting_key,
            assigned_kfrags=dict(assigned_kfrags),
            threshold=policy.threshold,
        )
        return treasure_map.encrypt(self._signer, recipient_card.encrypting_key)

    def card(self) -> "PublisherCard":
        return PublisherCard(verifying_key=self.verifying_key)


class PublisherCard:
    def __init__(self, verifying_key: PublicKey):
        self.verifying_key = verifying_key


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
        self, encrypted_tmap: EncryptedTreasureMap, publisher_card: PublisherCard
    ) -> TreasureMap:
        return encrypted_tmap.decrypt(self._decrypting_key, publisher_card.verifying_key)

    def decrypt_message_kit(
        self,
        message_kit: MessageKit,
        treasure_map: TreasureMap,
        vcfrags: Iterable[VerifiedCapsuleFrag],
    ) -> bytes:
        return message_kit.decrypt_reencrypted(
            self._decrypting_key, treasure_map.policy_encrypting_key, list(vcfrags)
        )


class RecipientCard:
    def __init__(self, encrypting_key: PublicKey, verifying_key: PublicKey):
        self.encrypting_key = encrypting_key
        self.verifying_key = verifying_key


class Ursula:
    def __init__(
        self,
        master_key: Optional[MasterKey] = None,
        identity_account: Optional[IdentityAccount] = None,
    ):
        self.__master_key = master_key or MasterKey.random()
        identity_account_ = identity_account or IdentityAccount.random()

        self.signer = self.__master_key.make_signer()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self.encrypting_key = self._decrypting_key.public_key()

        self.operator_address = identity_account_.address
        self.operator_signature = RecoverableSignature.from_be_bytes(
            identity_account_.sign_message(self.signer.verifying_key().to_compressed_bytes())
        )

    def peer_private_key(self) -> PeerPrivateKey:
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
    ) -> List[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]

    def __str__(self) -> str:
        operator_short = self.operator_address.checksum[:10]
        return f"Ursula(operator={operator_short})"
