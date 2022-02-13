import os

from eth_utils import to_canonical_address, to_checksum_address
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes


class EthAddress:

    @classmethod
    def random(cls):
        return cls(os.urandom(20))

    @classmethod
    def from_checksum(cls, address):
        return cls(to_canonical_address(address))

    def __init__(self, address: bytes):
        self._address = address

    def __bytes__(self):
        return self._address

    def to_checksum(self):
        return to_checksum_address(self._address)

    def __str__(self):
        return self.to_checksum()

    def __eq__(self, other):
        return type(self) == type(other) and self._address == other._address

    def __hash__(self):
        return hash(self._address)


class EthAccount:

    @classmethod
    def from_payload(cls, payload, password):
        account = Account.decrypt(payload, password)
        return cls(account)

    @classmethod
    def random(cls):
        return cls(Account.create())

    def __init__(self, account):
        self._account = account
        self.address = EthAddress.from_checksum(account.address)

    def sign_message(self, message: bytes):
        signature = self._account.sign_message(encode_defunct(message))
        return to_standard_signature_bytes(signature.signature)
