from typing import Any

from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes

class Account:
    @staticmethod
    def decrypt(keyfile_json: str | dict[str, Any], password: bytes | str) -> HexBytes: ...
    @classmethod
    def from_key(cls, private_key: HexBytes) -> LocalAccount: ...
    @classmethod
    def create(cls) -> LocalAccount: ...
