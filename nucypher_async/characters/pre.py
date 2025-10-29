from typing import Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from ethereum_rpc import keccak
from attrs import frozen
from nucypher_core import (
    HRAC,
    Address,
    EncryptedKeyFrag,
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    EncryptedTreasureMap,
    MessageKit,
    SessionStaticKey,
    ThresholdDecryptionRequest,
    ThresholdDecryptionResponse,
    ThresholdMessageKit,
    TreasureMap,
)
from nucypher_core.ferveo import (
    AggregatedTranscript,
    CiphertextHeader,
    DecryptionSharePrecomputed,
    DecryptionShareSimple,
    Dkg,
    DkgPublicKey,
    FerveoVariant,
    Validator,
    ValidatorMessage,
)
from nucypher_core.umbral import (
    Capsule,
    PublicKey,
    RecoverableSignature,
    VerifiedCapsuleFrag,
    VerifiedKeyFrag,
    generate_kfrags,
    reencrypt,
)

from ..drivers.cbd import Ritual
from ..drivers.identity import IdentityAccount, IdentityAddress
from ..drivers.peer import PeerPrivateKey
from ..drivers.pre import PREAccount, PREAccountSigner
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


class DelegatorCard:
    def __init__(self, verifying_key: PublicKey):
        self.verifying_key = verifying_key


class Publisher:
    @classmethod
    def random(cls) -> "Publisher":
        return cls(MasterKey.random(), PREAccount.random())

    def __init__(self, master_key: MasterKey, pre_account: PREAccount):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()
        self._pre_account = pre_account
        self.pre_signer = PREAccountSigner(self._pre_account)
        self.pre_address = self._pre_account.address
        self.verifying_key = self._signer.verifying_key()

    def make_treasure_map(
        self,
        policy: Policy,
        recipient_card: "RecipientCard",
        assigned_kfrags: Mapping[Address, tuple[PublicKey, VerifiedKeyFrag]],
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


class Reencryptor:
    def __init__(
        self,
        master_key: MasterKey | None = None,
        identity_account: IdentityAccount | None = None,
    ):
        self.__master_key = master_key or MasterKey.random()
        self.identity_account = identity_account or IdentityAccount.random()

        self.signer = self.__master_key.make_signer()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self.encrypting_key = self._decrypting_key.public_key()

        self._dkg_keypair = self.__master_key.make_dkg_keypair()
        self.dkg_key = self._dkg_keypair.public_key()

        self.operator_address = self.identity_account.address
        self.operator_signature = RecoverableSignature.from_be_bytes(
            self.identity_account.sign_message(self.signer.verifying_key().to_compressed_bytes())
        )

    def make_peer_private_key(self) -> PeerPrivateKey:
        return self.__master_key.make_peer_private_key()

    def decrypt_kfrag(
        self,
        encrypted_kfrag: EncryptedKeyFrag,
        hrac: HRAC,
        publisher_card: PublisherCard,
    ) -> VerifiedKeyFrag:
        return encrypted_kfrag.decrypt(self._decrypting_key, hrac, publisher_card.verifying_key)

    def decrypt_threshold_decryption_request(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> ThresholdDecryptionRequest:
        shared_secret = self.__master_key.make_shared_secret(
            request.ritual_id, request.requester_public_key
        )
        return request.decrypt(shared_secret)

    def encrypt_threshold_decryption_response(
        self,
        response: ThresholdDecryptionResponse,
        requester_public_key: SessionStaticKey,
    ) -> EncryptedThresholdDecryptionResponse:
        shared_secret = self.__master_key.make_shared_secret(
            response.ritual_id, requester_public_key
        )
        return response.encrypt(shared_secret)

    def reencrypt(
        self, verified_kfrag: VerifiedKeyFrag, capsules: Iterable[Capsule]
    ) -> list[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]

    def derive_decryption_share(
        self,
        ritual: Ritual,
        staking_provider_address: IdentityAddress,
        validators: Sequence[Validator],
        ciphertext_header: CiphertextHeader,
        aad: bytes,
        variant: FerveoVariant,
    ) -> Union[DecryptionShareSimple, DecryptionSharePrecomputed]:
        me = Validator(address=staking_provider_address.checksum, public_key=self.dkg_key)
        dkg = Dkg(
            tau=ritual.id,
            # CHECK: is this always equal to the number of participants?
            shares_num=ritual.dkg_size,
            security_threshold=ritual.threshold,
            validators=validators,
            me=me,
        )

        if variant == FerveoVariant.Simple:
            return ritual.aggregated_transcript.create_decryption_share_simple(
                dkg=dkg,
                ciphertext_header=ciphertext_header,
                aad=aad,
                validator_keypair=self._dkg_keypair,
            )
        elif variant == FerveoVariant.Precomputed:
            return ritual.aggregated_transcript.create_decryption_share_precomputed(
                dkg=dkg,
                ciphertext_header=ciphertext_header,
                aad=aad,
                validator_keypair=self._dkg_keypair,
            )
        else:
            raise NotImplementedError

    def __str__(self) -> str:
        operator_short = self.operator_address.checksum[:10]
        return f"Ursula(operator={operator_short})"
