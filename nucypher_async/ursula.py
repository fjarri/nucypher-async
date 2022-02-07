from typing import List

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from nucypher_core import EncryptedKeyFrag, HRAC
from nucypher_core.umbral import (
    SecretKey, Signer, PublicKey, VerifiedKeyFrag, VerifiedCapsuleFrag, reencrypt)

from .drivers.rest_client import SSLContact


class Ursula:

    def __init__(self, staker_address=None, domain="mainnet"):

        import os
        self.staker_address = os.urandom(20) # staker_address
        self.domain = domain

        # TODO: create from the main seed
        self._worker_account = Account.create()
        self.signer = Signer(SecretKey.random())
        self._decrypting_key = SecretKey.random()
        self.encrypting_key = self._decrypting_key.public_key()

        evidence = self._worker_account.sign_message(
            encode_defunct(bytes(self.signer.verifying_key())))

        self.decentralized_identity_evidence = to_standard_signature_bytes(evidence.signature)

    def decrypt_kfrag(self, encrypted_kfrag: EncryptedKeyFrag, hrac: HRAC, publisher_verifying_key: PublicKey) -> VerifiedKeyFrag:
        return encrypted_kfrag.decrypt(self._decrypting_key, hrac, publisher_verifying_key)

    def reencrypt(self, verified_kfrag: VerifiedKeyFrag, capsules) -> List[VerifiedCapsuleFrag]:
        return [reencrypt(capsule, verified_kfrag) for capsule in capsules]


class RemoteUrsula:

    def __init__(self, metadata, worker_address):
        self.metadata = metadata
        self.worker_address = worker_address

        self.ssl_contact = SSLContact.from_metadata(metadata)
