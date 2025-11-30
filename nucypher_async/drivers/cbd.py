from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from enum import Enum
from typing import cast

import arrow
from attrs import frozen
from eth_account import Account
from eth_account.signers.local import LocalAccount
from ethereum_rpc import Address, Amount
from nucypher_core import SessionStaticKey
from nucypher_core.ferveo import (
    AggregatedTranscript,
    CiphertextHeader,
    DkgPublicKey,
    FerveoPublicKey,
    Transcript,
)
from pons import (
    AccountSigner,
    Client,
    ClientSession,
    ContractABI,
    DeployedContract,
    Event,
    Method,
    Mutability,
    abi,
)
from pons.http_provider import HTTPProvider

from ..domain import Domain
from .identity import IdentityAddress

# Corresponds to BLS12381.G1Point
DkgPublicKeyStruct = abi.struct(word0=abi.bytes(32), word1=abi.bytes(16))

# Corresponds to BLS12381.G2Point
FerveoPublicKeyStruct = abi.struct(word0=abi.bytes(32), word1=abi.bytes(32), word2=abi.bytes(32))

ParticipantStruct = abi.struct(
    provider=abi.address,
    aggregated=abi.bool,
    transcript=abi.bytes(),
    decryptionRequestStaticKey=abi.bytes(),
)

RitualStruct = abi.struct(
    initiator=abi.address,
    initTimestamp=abi.uint(32),
    endTimestamp=abi.uint(32),
    totalTranscripts=abi.uint(16),
    totalAggregations=abi.uint(16),
    authority=abi.address,
    dkgSize=abi.uint(16),
    threshold=abi.uint(16),
    aggregationMismatch=abi.bool,
    accessController=abi.address,
    publicKey=DkgPublicKeyStruct,
    aggregatedTranscript=abi.bytes(),
    participant=ParticipantStruct[...],
)


# nucypher_contracts::Coordinator.sol
_COORDINATOR_ABI = ContractABI(
    events=[
        Event(
            name="StartRitual",
            fields=dict(
                ritualId=abi.uint(32), authority=abi.address, participants=abi.address[...]
            ),
            indexed={"ritualId", "authority"},
        )
    ],
    methods=[
        Method(
            name="isRitualActive",
            mutability=Mutability.VIEW,
            inputs=dict(ritualId=abi.uint(32)),
            outputs=abi.bool,
        ),
        Method(
            name="isParticipant",
            mutability=Mutability.VIEW,
            inputs=dict(ritualId=abi.uint(32), provider=abi.address),
            outputs=abi.bool,
        ),
        Method(
            name="rituals",
            mutability=Mutability.VIEW,
            inputs=[abi.uint(256)],
            outputs=RitualStruct,
        ),
        Method(
            name="getParticipants",
            mutability=Mutability.VIEW,
            inputs=dict(ritualId=abi.uint(32)),
            outputs=ParticipantStruct[...],
        ),
        Method(
            name="getRitualState",
            mutability=Mutability.VIEW,
            inputs=dict(ritualId=abi.uint(32)),
            outputs=abi.uint(8),
        ),
        Method(
            name="getRitualIdFromPublicKey",
            mutability=Mutability.VIEW,
            inputs=dict(dkgPublicKey=DkgPublicKeyStruct),
            outputs=abi.uint(32),
        ),
        Method(
            name="getProviderPublicKey",
            mutability=Mutability.VIEW,
            inputs=dict(provider=abi.address, ritual_id=abi.uint(256)),
            outputs=FerveoPublicKeyStruct,
        ),
        Method(
            name="initiateRitual",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(
                feeModel=abi.address,
                providers=abi.address[...],
                authority=abi.address,
                duration=abi.uint(32),
                accessController=abi.address,
            ),
            outputs=abi.uint(32),
        ),
    ],
)


class CBDAddress(Address):
    pass


@frozen
class OnChainRitual:
    id: int
    initiator: CBDAddress
    init_timestamp: arrow.Arrow
    end_timestamp: arrow.Arrow
    total_transcripts: int
    total_aggregations: int
    authority: CBDAddress
    dkg_size: int
    threshold: int
    aggregation_mismatch: bool
    access_controller: CBDAddress
    public_key: DkgPublicKey
    aggregated_transcript: AggregatedTranscript
    participant: "list[OnChainRitual.Participant]"

    @frozen
    class Participant:
        """Ritual participant."""

        provider: IdentityAddress
        share_index: int
        aggregated: bool
        transcript: Transcript | None
        decryption_request_static_key: SessionStaticKey

    class State(Enum):
        """Ritual state."""

        NON_INITIATED = 0
        DKG_AWAITING_TRANSCRIPTS = 1
        DKG_AWAITING_AGGREGATIONS = 2
        DKG_TIMEOUT = 3
        DKG_INVALID = 4
        ACTIVE = 5
        EXPIRED = 6

    @property
    def providers(self) -> list[IdentityAddress]:
        return [p.provider for p in self.participant]


class BaseContracts:
    COORDINATOR: CBDAddress


class LynxContracts(BaseContracts):
    """Registry for Polygon-Mumbai."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    COORDINATOR = CBDAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class TapirContracts(BaseContracts):
    """Registry for Polygon-Mumbai."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    COORDINATOR = CBDAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class MainnetContracts(BaseContracts):
    """Registry for Polygon-Mainnet."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    COORDINATOR = CBDAddress.from_hex("0xB0194073421192F6Cf38d72c791Be8729721A0b3")


class CBDAmount(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} CBD"


class CBDAccount:
    @classmethod
    def random(cls) -> "CBDAccount":
        return cls(Account.create())

    def __init__(self, account: LocalAccount):
        self._account = account
        self.address = CBDAddress.from_hex(account.address)


class CBDAccountSigner(AccountSigner):
    def __init__(self, cbd_account: CBDAccount):
        super().__init__(cbd_account._account)  # noqa: SLF001

    @property
    def address(self) -> CBDAddress:
        return CBDAddress(bytes(super().address))


class CBDClient:
    @classmethod
    def from_endpoint(cls, url: str, domain: Domain) -> "CBDClient":
        assert url.startswith("https://")
        provider = HTTPProvider(url)
        client = Client(provider)
        return cls(client, domain)

    def __init__(self, backend_client: Client, domain: Domain):
        self._client = backend_client

        registry: type[BaseContracts]
        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.LYNX:
            registry = LynxContracts
        elif domain == Domain.TAPIR:
            registry = TapirContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._coordinator = DeployedContract(address=registry.COORDINATOR, abi=_COORDINATOR_ABI)

    @asynccontextmanager
    async def session(self) -> AsyncIterator["CBDClientSession"]:
        async with self._client.session() as backend_session:
            yield CBDClientSession(self, backend_session)


class CBDClientSession:
    def __init__(self, cbd_client: CBDClient, backend_session: ClientSession):
        self._cbd_client = cbd_client
        self._backend_session = backend_session
        self._coordinator = self._cbd_client._coordinator  # noqa: SLF001

    async def is_ritual_active(self, ritual_id: int) -> bool:
        call = self._coordinator.method.isRitualActive(ritual_id)
        return cast("bool", await self._backend_session.call(call))

    async def is_participant(self, ritual_id: int, address: IdentityAddress) -> bool:
        call = self._coordinator.method.isParticipant(ritual_id, address)
        return cast("bool", await self._backend_session.call(call))

    async def is_authorized(
        self, ritual_id: int, evidence: bytes, ciphertext_header: CiphertextHeader
    ) -> bool:
        # TODO: this comes from the access controller contract
        raise NotImplementedError

    async def get_ritual(self, ritual_id: int) -> "OnChainRitual":
        call = self._coordinator.method.rituals(ritual_id)
        ritual = await self._backend_session.call(call)

        # TODO: workaround for https://github.com/nucypher/ferveo/issues/209
        # The `AggregatedTranscript` in `ferveo` has an additional field (dkg public key)
        # compared to the aggregated transcript saved on chain.
        # Since we use serde/bincode in rust, we need a metadata field for the public key,
        # which is the field size, as 8 bytes in little-endian.
        public_key = DkgPublicKey.from_bytes(
            ritual["publicKey"]["word0"] + ritual["publicKey"]["word1"]
        )
        public_key_metadata = b"0\x00\x00\x00\x00\x00\x00\x00"
        transcript = ritual["aggregatedTranscript"] + public_key_metadata + bytes(public_key)
        aggregated_transcript = AggregatedTranscript.from_bytes(transcript)

        return OnChainRitual(
            id=ritual_id,
            initiator=CBDAddress(bytes(ritual["initiator"])),
            init_timestamp=arrow.get(ritual["initTimestamp"]),
            end_timestamp=arrow.get(ritual["endTimestamp"]),
            total_transcripts=ritual["totalTranscripts"],
            total_aggregations=ritual["totalAggregations"],
            authority=CBDAddress(bytes(ritual["authority"])),
            dkg_size=ritual["dkgSize"],
            threshold=ritual["threshold"],
            aggregation_mismatch=ritual["aggregationMismatch"],
            access_controller=CBDAddress(bytes(ritual["accessController"])),
            public_key=public_key,
            aggregated_transcript=aggregated_transcript,
            # The contract assumes the share id is equal to the index
            # of the participant in the list.
            participant=[
                OnChainRitual.Participant(share_index=idx, **struct)
                for idx, struct in enumerate(ritual["participants"])
            ],
        )

    async def get_provider_public_key(
        self, provider: IdentityAddress, ritual_id: int
    ) -> FerveoPublicKey:
        call = self._coordinator.method.getProviderPublicKey(provider, ritual_id)
        key = await self._backend_session.call(call)
        return FerveoPublicKey.from_bytes(key["word0"] + key["word1"] + key["word2"])

    async def initiate_ritual(
        self,
        signer: CBDAccountSigner,
        fee_model: CBDAddress,
        providers: Sequence[IdentityAddress],
        authority: IdentityAddress,  # TODO: can it be different from the signer's address?
        duration: int,
        access_controller: IdentityAddress,
    ) -> int:
        call = self._coordinator.method.initiateRitual(
            fee_model, providers, authority, duration, access_controller
        )
        event = self._coordinator.event.StartRitual
        events = await self._backend_session.transact(signer, call, return_events=[event])
        assert len(events[event]) == 1
        return cast("int", events[event][0]["ritualId"])

    async def get_ritual_state(self, ritual_id: int) -> OnChainRitual.State:
        call = self._coordinator.method.getRitualState(ritual_id)
        state = await self._backend_session.call(call)
        return OnChainRitual.State(state)

    async def get_ritual_id_from_public_key(self, public_key: DkgPublicKey) -> int:
        pk_bytes = bytes(public_key)
        pk_word0 = pk_bytes[:32]
        pk_word1 = pk_bytes[32:]
        call = self._coordinator.method.getRitualIdFromPublicKey((pk_word0, pk_word1))
        ritual_id = await self._backend_session.call(call)
        assert isinstance(ritual_id, int)
        return ritual_id

    async def get_participants(self, ritual_id: int) -> list[OnChainRitual.Participant]:
        call = self._coordinator.method.getParticipants(ritual_id)
        participants = await self._backend_session.call(call)
        return [
            OnChainRitual.Participant(
                provider=IdentityAddress(bytes(participant["provider"])),
                # The contract assumes the share id is equal to the index
                # of the participant in the list.
                share_index=idx,
                aggregated=participant["aggregated"],
                transcript=Transcript.from_bytes(participant["transcript"])
                if participant["transcript"]
                else None,
                decryption_request_static_key=SessionStaticKey.from_bytes(
                    participant["decryption_request_static_key"]
                ),
            )
            for idx, participant in enumerate(participants)
        ]
