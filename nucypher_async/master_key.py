from secrets import token_bytes
from typing import TypedDict

import arrow
from mnemonic.mnemonic import Mnemonic
from nucypher_core import SessionSecretFactory, SessionSharedSecret, SessionStaticKey
from nucypher_core.ferveo import Keypair as FerveoKeypair
from nucypher_core.umbral import SecretKey, SecretKeyFactory, Signer

from .drivers.peer import PeerPrivateKey
from .utils.passwords import (
    SecretBoxAuthenticationError,
    derive_key_material_from_password,
    secret_box_decrypt,
    secret_box_encrypt,
)


class NucypherKeystore(TypedDict):
    password_salt: str
    wrapper_salt: str
    key: str
    version: str
    created: str


class EncryptedMasterKey:
    @classmethod
    def from_payload(cls, payload: NucypherKeystore) -> "EncryptedMasterKey":
        password_salt = bytes.fromhex(payload["password_salt"])
        wrapper_salt = bytes.fromhex(payload["wrapper_salt"])
        encrypted_key = bytes.fromhex(payload["key"])
        return cls(encrypted_key, password_salt, wrapper_salt)

    def __init__(self, encrypted_key: bytes, password_salt: bytes, wrapper_salt: bytes):
        self.encrypted_key = encrypted_key
        self.password_salt = password_salt
        self.wrapper_salt = wrapper_salt

    def decrypt(self, password: str) -> "MasterKey":
        key_material = derive_key_material_from_password(
            password=password.encode(), salt=self.password_salt
        )
        try:
            secret = secret_box_decrypt(
                key_material=key_material,
                ciphertext=self.encrypted_key,
                salt=self.wrapper_salt,
            )
        except SecretBoxAuthenticationError as exc:
            raise RuntimeError("Authentication failed") from exc

        return MasterKey(secret)

    def to_payload(self) -> NucypherKeystore:
        return dict(
            version="2.0",
            # TODO: do we need this field? Don't want to pass Clock here
            created=str(arrow.utcnow().timestamp()),
            key=self.encrypted_key.hex(),
            password_salt=self.password_salt.hex(),
            wrapper_salt=self.wrapper_salt.hex(),
        )


class MasterKey:
    @classmethod
    def random_mnemonic(cls) -> tuple[str, "MasterKey"]:
        mnemonic = Mnemonic("english")
        words = mnemonic.generate(strength=256)
        secret = bytes(mnemonic.to_entropy(words))
        return words, cls(secret)

    @classmethod
    def random(cls) -> "MasterKey":
        return cls(token_bytes(32))

    @classmethod
    def from_mnemonic(cls, words: str) -> "MasterKey":
        mnemonic = Mnemonic("english")
        secret = bytes(mnemonic.to_entropy(words))
        return cls(secret)

    def __init__(self, secret: bytes):
        self.__secret = secret
        self.__skf = SecretKeyFactory.from_secure_randomness(secret)

        size = SessionSecretFactory.seed_size()
        self.__ssf = SessionSecretFactory.from_secure_randomness(
            self.__skf.make_secret(b"NuCypher/threshold_request_decrypting")[:size]
        )

    def encrypt(self, password: str) -> EncryptedMasterKey:
        password_salt = token_bytes(16)
        key_material = derive_key_material_from_password(
            password=password.encode(), salt=password_salt
        )

        wrapper_salt = token_bytes(16)
        encrypted_key = secret_box_encrypt(
            plaintext=self.__secret,
            key_material=key_material,
            salt=wrapper_salt,
        )
        return EncryptedMasterKey(encrypted_key, password_salt, wrapper_salt)

    def make_peer_private_key(self) -> PeerPrivateKey:
        secret = self.__skf.make_secret(b"NuCypher/tls")
        return PeerPrivateKey.from_seed(secret)

    def make_signer(self) -> Signer:
        return Signer(self.__skf.make_key(b"NuCypher/signing"))

    def make_decrypting_key(self) -> SecretKey:
        return self.__skf.make_key(b"NuCypher/decrypting")

    def make_delegating_key_factory(self) -> SecretKeyFactory:
        return self.__skf.make_factory(b"NuCypher/delegating")

    def make_dkg_keypair(self) -> FerveoKeypair:
        size = FerveoKeypair.secure_randomness_size()
        randomness = self.__skf.make_secret(b"NuCypher/ritualistic")[:size]
        return FerveoKeypair.from_secure_randomness(randomness)

    def make_shared_secret(
        self, ritual_id: int, requester_public_key: SessionStaticKey
    ) -> SessionSharedSecret:
        static_secret = self.__ssf.make_key(ritual_id.to_bytes(4, "big"))
        return static_secret.derive_shared_secret(requester_public_key)
