import os
from collections.abc import Iterable, Mapping, Sequence

from attrs import frozen
from ethereum_rpc import keccak
from nucypher_core import (
    AccessControlPolicy,
    Conditions,
    Context,
    EncryptedThresholdDecryptionRequest,
    EncryptedThresholdDecryptionResponse,
    SessionSharedSecret,
    SessionStaticKey,
    SessionStaticSecret,
    ThresholdDecryptionRequest,
    ThresholdDecryptionResponse,
    ThresholdMessageKit,
    encrypt_for_dkg,
)
from nucypher_core.ferveo import (
    AggregatedTranscript,
    DecryptionShareSimple,
    Dkg,
    DkgPublicKey,
    FerveoPublicKey,
    FerveoVariant,
    Transcript,
    Validator,
    ValidatorMessage,
    combine_decryption_shares_simple,
)

from ..blockchain.cbd import OnChainRitual
from ..blockchain.identity import IdentityAddress
from ._master_key import MasterKey


class Encryptor:
    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self._signer = self.__master_key.make_signer()

    def encrypt(
        self, ritual_pk: DkgPublicKey, plaintext: bytes, conditions: Conditions = Conditions("{}")
    ) -> ThresholdMessageKit:
        ciphertext, auth_data = encrypt_for_dkg(plaintext, ritual_pk, conditions)

        # authentication message for TACo
        # TODO: use the eth-* Signer object here as in the reference
        header_hash = keccak(bytes(ciphertext.header))
        authorization = self._signer.sign(header_hash).to_be_bytes()
        return ThresholdMessageKit(
            ciphertext=ciphertext,
            acp=AccessControlPolicy(auth_data=auth_data, authorization=authorization),
        )


@frozen
class ActiveRitual:
    id: int
    threshold: int
    aggregated_transcript: AggregatedTranscript
    participants: list["Participant"]

    @property
    def dkg_public_key(self) -> DkgPublicKey:
        return self.aggregated_transcript.public_key

    @classmethod
    def from_on_chain_ritual(
        cls, on_chain_ritual: OnChainRitual, validators: Mapping[IdentityAddress, FerveoPublicKey]
    ) -> "ActiveRitual":
        assert len(validators) == len(on_chain_ritual.participant)
        return cls(
            id=on_chain_ritual.id,
            threshold=on_chain_ritual.threshold,
            aggregated_transcript=on_chain_ritual.aggregated_transcript,
            participants=[
                Participant(
                    share_index=participant.share_index,
                    card=DkgNodeCard(public_key=validators[participant.provider]),
                    decryption_request_static_key=participant.decryption_request_static_key,
                )
                for participant in on_chain_ritual.participant
            ],
        )

    def _make_dkg_struct(self, me: "DkgNodeCard") -> Dkg:
        # TODO: the address argument to Validator has no effect on cryptographic operations,
        # to be removed in https://github.com/nucypher/ferveo/pull/220
        validators = [
            Validator(
                "0x" + os.urandom(20).hex(), participant.card.public_key, participant.share_index
            )
            for participant in self.participants
        ]
        local_validator = next(
            validator for validator in validators if validator.public_key == me.public_key
        )
        return Dkg(
            tau=self.id,
            shares_num=len(validators),
            security_threshold=self.threshold,
            validators=validators,
            me=local_validator,
        )

    @classmethod
    def _test_create(
        cls, ritual_id: int, nodes: Sequence["Decryptor"], threshold: int
    ) -> "ActiveRitual":
        shares_num = len(nodes)
        planned_participants = [
            PlannedParticipant(node.card(), share_index) for share_index, node in enumerate(nodes)
        ]
        participants = []
        transcripts = []
        for node in nodes:
            participant, transcript = node.participate_in_ritual(
                ritual_id, planned_participants, threshold
            )
            participants.append(participant)
            transcripts.append(transcript)

        validators = [
            Validator("0x" + os.urandom(20).hex(), node.public_key, share_index)
            for share_index, node in enumerate(nodes)
        ]
        dkg = Dkg(
            tau=ritual_id,
            shares_num=shares_num,
            security_threshold=threshold,
            validators=validators,
            me=validators[0],
        )
        aggregated_transcript = dkg.aggregate_transcripts(
            [
                ValidatorMessage(validator, transcript)
                for validator, transcript in zip(validators, transcripts, strict=True)
            ]
        )
        return cls(
            id=ritual_id,
            threshold=threshold,
            aggregated_transcript=aggregated_transcript,
            participants=participants,
        )

    def participant(self, card: "DkgNodeCard") -> "Participant":
        return next(participant for participant in self.participants if participant.card == card)


@frozen
class DkgNodeCard:
    public_key: FerveoPublicKey


@frozen
class PlannedParticipant:
    card: DkgNodeCard
    share_index: int


@frozen
class Participant:
    card: DkgNodeCard
    decryption_request_static_key: SessionStaticKey
    share_index: int


class Decryptor:
    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key
        self.__dkg_keypair = self.__master_key.make_dkg_keypair()
        self.public_key = self.__dkg_keypair.public_key()

    def card(self) -> DkgNodeCard:
        return DkgNodeCard(public_key=self.public_key)

    def participate_in_ritual(
        self, ritual_id: int, participants: Sequence[PlannedParticipant], threshold: int
    ) -> tuple[Participant, Transcript]:
        # TODO: the address argument to Validator has no effect on cryptographic operations,
        # to be removed in https://github.com/nucypher/ferveo/pull/220
        validators = [
            Validator(
                "0x" + os.urandom(20).hex(), participant.card.public_key, participant.share_index
            )
            for participant in participants
        ]
        local_validator = next(
            validator for validator in validators if validator.public_key == self.public_key
        )
        dkg = Dkg(
            tau=ritual_id,
            shares_num=len(validators),
            security_threshold=threshold,
            validators=validators,
            me=local_validator,
        )
        transcript = dkg.generate_transcript()
        return Participant(
            share_index=local_validator.share_index,
            card=self.card(),
            decryption_request_static_key=self.__master_key.make_session_static_key(ritual_id),
        ), transcript

    def decrypt_threshold_decryption_request(
        self, request: EncryptedThresholdDecryptionRequest
    ) -> ThresholdDecryptionRequest:
        shared_secret = self.__master_key.make_shared_secret(
            request.ritual_id, request.requester_public_key
        )
        return request.decrypt(shared_secret)

    def make_decryption_share(
        self,
        ritual: ActiveRitual,
        tdr: ThresholdDecryptionRequest,
    ) -> DecryptionShareSimple:
        if tdr.variant == FerveoVariant.Simple:
            return ritual.aggregated_transcript.create_decryption_share_simple(
                ritual._make_dkg_struct(self.card()),  # noqa: SLF001
                tdr.ciphertext_header,
                tdr.acp.aad(),
                self.__dkg_keypair,
            )
        if tdr.variant == FerveoVariant.Precomputed:
            # see https://github.com/nucypher/nucypher/issues/3636
            raise NotImplementedError("Precomputed variant is currently not supported")

        raise RuntimeError(f"Unknown Ferveo variant: {tdr.variant}")

    def make_threshold_decryption_response(
        self, ritual: ActiveRitual, decryption_share: DecryptionShareSimple
    ) -> ThresholdDecryptionResponse:
        # TODO (#38): need the serialization because of
        # https://github.com/nucypher/nucypher-core/issues/121
        return ThresholdDecryptionResponse(ritual.id, bytes(decryption_share))

    def encrypt_threshold_decryption_response(
        self, response: ThresholdDecryptionResponse, requester_public_key: SessionStaticKey
    ) -> EncryptedThresholdDecryptionResponse:
        shared_secret = self.__master_key.make_shared_secret(
            response.ritual_id, requester_public_key
        )
        return response.encrypt(shared_secret)


class Recipient:
    def __init__(self, master_key: MasterKey):
        self.__master_key = master_key

    def make_decryption_request(
        self,
        ritual_id: int,
        message_kit: ThresholdMessageKit,
        variant: FerveoVariant = FerveoVariant.Simple,
        context: Context | None = None,
    ) -> ThresholdDecryptionRequest:
        return ThresholdDecryptionRequest(
            ritual_id=ritual_id,
            variant=variant,
            ciphertext_header=message_kit.ciphertext_header,
            acp=message_kit.acp,
            context=context,
        )

    def encrypt_decryption_request(
        self, tdr: ThresholdDecryptionRequest, participant: Participant
    ) -> tuple[EncryptedThresholdDecryptionRequest, SessionSharedSecret]:
        requester_sk = SessionStaticSecret.random()
        requester_public_key = requester_sk.public_key()
        shared_secret = requester_sk.derive_shared_secret(participant.decryption_request_static_key)

        return tdr.encrypt(
            shared_secret=shared_secret,
            requester_public_key=requester_public_key,
        ), shared_secret

    def decrypt_threshold_decryption_response(
        self, etdr: EncryptedThresholdDecryptionResponse, requester_public_key: SessionSharedSecret
    ) -> ThresholdDecryptionResponse:
        return etdr.decrypt(requester_public_key)

    @staticmethod
    def decrypt_with_responses(
        message_kit: ThresholdMessageKit, responses: Iterable[ThresholdDecryptionResponse]
    ) -> bytes:
        # TODO (#38): need the deserialization because of
        # https://github.com/nucypher/nucypher-core/issues/121
        decryption_shares = [
            DecryptionShareSimple.from_bytes(response.decryption_share) for response in responses
        ]

        # TODO (#39): need the conversion because of
        # https://github.com/nucypher/nucypher-core/issues/119
        return bytes(
            message_kit.decrypt_with_shared_secret(
                combine_decryption_shares_simple(decryption_shares)
            )
        )
