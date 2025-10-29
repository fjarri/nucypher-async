from attrs import frozen
from ethereum_rpc import keccak
from nucypher_core import AccessControlPolicy, Conditions, ThresholdMessageKit, encrypt_for_dkg
from nucypher_core.ferveo import DkgPublicKey

from ..master_key import MasterKey


class CBDEncryptor:
    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()

    def encrypt(self, ritual_pk: DkgPublicKey, plaintext: bytes) -> ThresholdMessageKit:
        # TODO: process conditions
        access_conditions = Conditions("{}")

        ciphertext, auth_data = encrypt_for_dkg(plaintext, ritual_pk, access_conditions)

        # authentication message for TACo
        # TODO: use the eth-* Signer object here as in the reference
        header_hash = keccak(bytes(ciphertext.header))
        authorization = self._signer.sign(bytes(ciphertext.header)).to_be_bytes()

        return ThresholdMessageKit(
            ciphertext=ciphertext,
            acp=AccessControlPolicy(auth_data=auth_data, authorization=authorization),
        )
