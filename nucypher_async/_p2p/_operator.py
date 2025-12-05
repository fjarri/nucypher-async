from nucypher_core.umbral import RecoverableSignature

from ..blockchain.identity import IdentityAccount
from ..master_key import MasterKey
from ._keys import PeerPrivateKey


class Operator:
    def __init__(self, master_key: MasterKey, identity_account: IdentityAccount):
        self.__master_key = master_key
        self.signer = master_key.make_signer()
        self.__identity_account = identity_account

        self.verifying_key = self.signer.verifying_key()
        self.address = identity_account.address
        self.signature = RecoverableSignature.from_be_bytes(
            identity_account.sign_message(self.verifying_key.to_compressed_bytes())
        )
        self.peer_private_key = PeerPrivateKey(self.__master_key.make_ssl_private_key())
