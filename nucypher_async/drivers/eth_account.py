import os

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from pons.types import Address


class EthAccount:

    @classmethod
    def from_payload(cls, payload, password):
        pk = Account.decrypt(payload, password)
        account = Account.from_key(pk)
        return cls(account)

    @classmethod
    def random(cls):
        return cls(Account.create())

    def __init__(self, account):
        self._account = account
        self.address = Address.from_hex(account.address)

    def sign_message(self, message: bytes):
        signature = self._account.sign_message(encode_defunct(message))
        return to_standard_signature_bytes(signature.signature)
