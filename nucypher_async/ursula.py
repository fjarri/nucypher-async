from typing import List, Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from nucypher_core import EncryptedKeyFrag, HRAC
from nucypher_core.umbral import (
    SecretKey, Signer, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag, reencrypt)

from .drivers.eth_account import EthAccount
from .drivers.eth_client import Address
from .drivers.rest_client import SSLContact
from .master_key import MasterKey


class Ursula:

    def __init__(
            self,
            master_key: Optional[MasterKey] = None,
            eth_account: Optional[EthAccount] = None,
            domain="mainnet"):

        self.domain = domain

        if not master_key:
            master_key = MasterKey.random()
        self.__master_key = master_key

        if not eth_account:
            eth_account = EthAccount.random()
        self.__eth_account = eth_account

        self.signer = self.__master_key.make_signer()
        self._decrypting_key = self.__master_key.make_decrypting_key()
        self.encrypting_key = self._decrypting_key.public_key()

        self.operator_address = self.__eth_account.address
        self.decentralized_identity_evidence = self.__eth_account.sign_message(bytes(self.signer.verifying_key()))

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
        self.metadata = metadata
        self.staker_address = Address(self.metadata.payload.staker_address)
        self.operator_address = operator_address

        self.ssl_contact = SSLContact.from_metadata(metadata)

    def __str__(self):
        staker_short = self.staker_address.as_checksum()[:10]
        return f"RemoteUrsula(staker={staker_short})"
