from typing import List, Optional

from nucypher_core import EncryptedKeyFrag, HRAC
from nucypher_core.umbral import (
    SecretKey,
    Signer,
    PublicKey,
    VerifiedKeyFrag,
    VerifiedCapsuleFrag,
    reencrypt,
)

from .drivers.identity import IdentityAccount
from .drivers.peer import PeerPrivateKey
from .master_key import MasterKey


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
        self.operator_signature = identity_account_.sign_message(bytes(self.signer.verifying_key()))

    def peer_private_key(self):
        return self.__master_key.make_peer_private_key()

    def decrypt_kfrag(
        self,
        encrypted_kfrag: EncryptedKeyFrag,
        hrac: HRAC,
        publisher_verifying_key: PublicKey,
    ) -> VerifiedKeyFrag:
        return encrypted_kfrag.decrypt(self._decrypting_key, hrac, publisher_verifying_key)

    def reencrypt(self, verified_kfrag: VerifiedKeyFrag, capsules) -> List[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]

    def __str__(self):
        operator_short = self.operator_address.checksum[:10]
        return f"Ursula(operator={operator_short})"
