from typing import List, Optional

from nucypher_core import EncryptedKeyFrag, HRAC
from nucypher_core.umbral import (
    SecretKey, Signer, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag, reencrypt)

from .drivers.identity import IdentityAddress, IdentityAccount
from .drivers.rest_client import SSLContact
from .master_key import MasterKey


class Ursula:

    def __init__(
            self,
            master_key: Optional[MasterKey] = None,
            identity_account: Optional[IdentityAccount] = None):

        if not master_key:
            master_key = MasterKey.random()
        self.__master_key = master_key

        if not identity_account:
            identity_account = IdentityAccount.random()

        self.signer = self.__master_key.make_signer()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self.encrypting_key = self._decrypting_key.public_key()

        self.operator_address = identity_account.address
        self.operator_signature = identity_account.sign_message(bytes(self.signer.verifying_key()))

    def make_ssl_private_key(self):
        return self.__master_key.make_ssl_private_key()

    def decrypt_kfrag(self, encrypted_kfrag: EncryptedKeyFrag, hrac: HRAC, publisher_verifying_key: PublicKey) -> VerifiedKeyFrag:
        return encrypted_kfrag.decrypt(self._decrypting_key, hrac, publisher_verifying_key)

    def reencrypt(self, verified_kfrag: VerifiedKeyFrag, capsules) -> List[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]

    def __str__(self):
        operator_short = self.operator_address.as_checksum()[:10]
        return f"Ursula(operator={operator_short})"


class RemoteUrsula:

    def __init__(self, metadata, operator_address):
        payload = metadata.payload

        self.metadata = metadata
        self.staking_provider_address = IdentityAddress(payload.staking_provider_address)
        self.operator_address = operator_address
        self.verifying_key = payload.verifying_key
        self.encrypting_key = payload.encrypting_key

        self.ssl_contact = SSLContact.from_metadata(metadata)

    def __str__(self):
        return f"RemoteUrsula({self.staking_provider_address.as_checksum()})"
