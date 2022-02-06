from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from nucypher_core.umbral import SecretKey, Signer

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


class RemoteUrsula:

    def __init__(self, metadata, worker_address):
        self.metadata = metadata
        self.worker_address = worker_address

        self.ssl_contact = SSLContact.from_metadata(metadata)
