from secrets import token_bytes

import arrow
from mnemonic.mnemonic import Mnemonic
from nucypher_core.umbral import SecretKeyFactory, SecretKey, Signer

from .drivers.peer import PeerPrivateKey
from .utils.passwords import (
    derive_key_material_from_password,
    secret_box_decrypt,
    secret_box_encrypt,
    SecretBoxAuthenticationError,
    )


class EncryptedMasterKey:

    @classmethod
    def from_payload(cls, payload):
        password_salt = bytes.fromhex(payload['password_salt'])
        wrapper_salt = bytes.fromhex(payload['wrapper_salt'])
        encrypted_key = bytes.fromhex(payload['key'])
        return cls(encrypted_key, password_salt, wrapper_salt)

    def __init__(self, encrypted_key: bytes, password_salt: bytes, wrapper_salt: bytes):
        self.encrypted_key = encrypted_key
        self.password_salt = password_salt
        self.wrapper_salt = wrapper_salt

    def decrypt(self, password):
        key_material = derive_key_material_from_password(
            password=password.encode(), salt=self.password_salt)
        try:
            secret = secret_box_decrypt(key_material=key_material,
                                        ciphertext=self.encrypted_key,
                                        salt=self.wrapper_salt)
        except SecretBoxAuthenticationError as e:
            raise RuntimeError("Authentication failed") from e

        return MasterKey(secret)

    def to_payload(self):
        return dict(
            version="2.0",
            # TODO: do we need this field? Don't want to pass Clock here
            created=str(arrow.utcnow().timestamp()),
            key=self.encrypted_key.hex(),
            password_salt=self.password_salt.hex(),
            wrapper_salt=self.wrapper_salt.hex())


class MasterKey:

    @classmethod
    def random_mnemonic(cls):
        mnemonic = Mnemonic('english')
        words = mnemonic.generate(strength=256)
        secret = bytes(mnemonic.to_entropy(words))
        return words, cls(secret)

    @classmethod
    def random(cls):
        return cls(token_bytes(32))

    @classmethod
    def from_mnemonic(cls, words: str):
        mnemonic = Mnemonic('english')
        secret = bytes(mnemonic.to_entropy(words))
        return cls(secret)

    def __init__(self, secret: bytes):
        self.__skf = SecretKeyFactory.from_secure_randomness(secret)

    def encrypt(self, password: str):
        password_salt = token_bytes(16)
        key_material = derive_key_material_from_password(password=password.encode(),
                                                         salt=password_salt)

        wrapper_salt = token_bytes(16)
        encrypted_key = secret_box_encrypt(plaintext=self.__skf.to_secret_bytes(),
                                           key_material=key_material,
                                           salt=wrapper_salt)
        return EncryptedMasterKey(encrypted_key, password_salt, wrapper_salt)

    def make_peer_private_key(self):
        sk = self.__skf.make_key(b'NuCypher/tls')
        return PeerPrivateKey(sk.to_secret_bytes())

    def make_signer(self):
        return Signer(self.__skf.make_key(b'NuCypher/signing'))

    def make_decrypting_key(self):
        return self.__skf.make_key(b'NuCypher/decrypting')

    def make_delegating_key_factory(self):
        return self.__skf.make_factory(b'NuCypher/delegating')
