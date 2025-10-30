from ethereum_rpc import keccak
from nucypher_core import (
    AccessControlPolicy,
    Conditions,
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    SessionStaticKey,
    ThresholdDecryptionRequest,
    ThresholdDecryptionResponse,
    ThresholdMessageKit,
    encrypt_for_dkg,
)
from nucypher_core.ferveo import (
    AggregatedTranscript,
    CiphertextHeader,
    DecryptionShareSimple,
    Dkg,
    DkgPublicKey,
    FerveoVariant,
    Validator,
)

from ..master_key import MasterKey


class Encryptor:
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
        authorization = self._signer.sign(header_hash).to_be_bytes()

        return ThresholdMessageKit(
            ciphertext=ciphertext,
            acp=AccessControlPolicy(auth_data=auth_data, authorization=authorization),
        )


class Decryptor:
    def __init__(
        self,
        master_key: MasterKey | None = None,
    ):
        self.__master_key = master_key or MasterKey.random()
        self.__dkg_keypair = self.__master_key.make_dkg_keypair()
        self.ritual_public_key = self.__dkg_keypair.public_key()

    def decrypt_threshold_decryption_request(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> ThresholdDecryptionRequest:
        shared_secret = self.__master_key.make_shared_secret(
            request.ritual_id, request.requester_public_key
        )
        return request.decrypt(shared_secret)

    def produce_decryption_share(
        self,
        me: Validator,
        nodes: list[Validator],
        threshold: int,
        shares: int,
        ritual_id: int,
        aggregated_transcript: AggregatedTranscript,
        ciphertext_header: CiphertextHeader,
        aad: bytes,
        variant: FerveoVariant,
    ) -> DecryptionShareSimple:
        dkg = Dkg(
            tau=ritual_id, shares_num=shares, security_threshold=threshold, validators=nodes, me=me
        )

        if variant == FerveoVariant.Simple:
            return aggregated_transcript.create_decryption_share_simple(
                dkg=dkg,
                ciphertext_header=ciphertext_header,
                aad=aad,
                validator_keypair=self.__dkg_keypair,
            )
        if variant == FerveoVariant.Precomputed:
            # see https://github.com/nucypher/nucypher/issues/3636
            raise NotImplementedError("Precomputed variant is currently not supported")

        raise RuntimeError(f"Unknown Ferveo variant: {variant}")

    def encrypt_threshold_decryption_response(
        self, response: ThresholdDecryptionResponse, requester_public_key: SessionStaticKey
    ) -> EncryptedThresholdDecryptionResponse:
        shared_secret = self.__master_key.make_shared_secret(
            response.ritual_id, requester_public_key
        )
        return response.encrypt(shared_secret)
