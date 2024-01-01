"""
A rough draft of the Eth driver.
TODO:
- finish up registries properly (include ABIs in the registry class,
  merge ABIs with contract addresses, add registries for different networks)
- find a way to get ABIs automatically
- find a way to test transactions
- set gas value properly (estimate gas, gas strategies)
- add newtypes for currencies instead of just using wei
"""

from contextlib import asynccontextmanager
from enum import Enum
from typing import AsyncIterator, List, Optional, Sequence, Type, cast

import arrow
from attrs import frozen
from eth_account import Account
from eth_account.signers.base import BaseAccount
from nucypher_core import HRAC, SessionStaticKey
from nucypher_core.ferveo import AggregatedTranscript, DkgPublicKey, Transcript
from pons import (
    AccountSigner,
    Address,
    Amount,
    Client,
    ClientSession,
    ContractABI,
    DeployedContract,
    Event,
    HTTPProvider,
    Method,
    Mutability,
    Signer,
    abi,
)

from ..domain import Domain
from .identity import IdentityAddress

DkgPublicKeyStruct = abi.struct(word0=abi.bytes(32), word1=abi.bytes(16))


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
            name="rituals",
            mutability=Mutability.VIEW,
            inputs=[abi.uint(256)],
            outputs=abi.struct(
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
            ),
        ),
        Method(
            name="getParticipants",
            mutability=Mutability.VIEW,
            inputs=dict(ritualId=abi.uint(32)),
            outputs=abi.struct(
                provider=abi.address,
                aggregated=abi.bool,
                transcript=abi.bytes(),
                decryptionRequestStaticKey=abi.bytes(),
            )[...],
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
            name="initiateRitual",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(
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


class BaseContracts:
    COORDINATOR: CBDAddress


class LynxContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    COORDINATOR = CBDAddress.from_hex("0x0000000000000000000000000000000000000000")


class TapirContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    COORDINATOR = CBDAddress.from_hex("0x0000000000000000000000000000000000000000")


class MainnetContracts(BaseContracts):
    """
    Registry for Polygon-Mainnet.
    """

    COORDINATOR = CBDAddress.from_hex("0x0000000000000000000000000000000000000000")


class AmountMATIC(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} MATIC"


class CBDAccount:
    @classmethod
    def random(cls) -> "CBDAccount":
        return cls(Account.create())

    def __init__(self, account: BaseAccount):
        self._account = account
        self.address = CBDAddress.from_hex(account.address)


class CBDAccountSigner(AccountSigner):
    def __init__(self, account: CBDAccount):
        super().__init__(account._account)

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

        registry: Type[BaseContracts]
        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.LYNX:
            registry = LynxContracts
        elif domain == Domain.TAPIR:
            registry = TapirContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._contract = DeployedContract(
            address=registry.SUBSCRIPTION_MANAGER, abi=_SUBSCRIPTION_MANAGER_ABI
        )
        self._coordinator = DeployedContract(address=registry.COORDINATOR, abi=_COORDINATOR_ABI)

    @asynccontextmanager
    async def session(self) -> AsyncIterator["CBDClientSession"]:
        async with self._client.session() as backend_session:
            yield CBDClientSession(self, backend_session)


class CBDClientSession:
    def __init__(self, client: CBDClient, backend_session: ClientSession):
        self._client = client
        self._backend_session = backend_session
        self._contract = self._client._contract
        self._coordinator = self._client._coordinator

    async def is_policy_active(self, hrac: HRAC) -> bool:
        is_active = await self._backend_session.eth_call(
            self._contract.method.isPolicyActive(bytes(hrac))
        )
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(bool, is_active)

    async def get_policy_cost(self, shares: int, policy_start: int, policy_end: int) -> AmountMATIC:
        amount = await self._backend_session.eth_call(
            self._contract.method.getPolicyCost(shares, policy_start, policy_end)
        )
        return AmountMATIC.wei(amount)

    async def create_policy(
        self,
        signer: Signer,
        hrac: HRAC,
        shares: int,
        policy_start: int,
        policy_end: int,
    ) -> None:
        amount = await self.get_policy_cost(shares, policy_start, policy_end)
        call = self._contract.method.createPolicy(
            bytes(hrac), signer.address, shares, policy_start, policy_end
        )
        await self._backend_session.transact(signer, call, amount=amount)

    async def get_ritual(self, ritual_id: int) -> "Ritual":
        call = self._coordinator.method.rituals(ritual_id)
        ritual = await self._backend_session.eth_call(call)
        return Ritual(
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
            public_key=DkgPublicKey.from_bytes(
                ritual["publicKey"]["word0"] + ritual["publicKey"]["word1"]
            ),
            aggregated_transcript=AggregatedTranscript.from_bytes(ritual["aggregatedTranscript"]),
        )

    async def get_participants(self, ritual_id: int) -> List["Ritual.Participant"]:
        call = self._coordinator.method.getParticipants(ritual_id)
        participants = await self._backend_session.eth_call(call)
        return [
            Ritual.Participant(
                provider=IdentityAddress(bytes(participant["provider"])),
                aggregated=participant["aggregated"],
                transcript=Transcript.from_bytes(participant["transcript"])
                if participant["transcript"]
                else None,
                decryption_request_static_key=SessionStaticKey.from_bytes(
                    participant["decryption_request_static_key"]
                ),
            )
            for participant in participants
        ]

    async def get_ritual_state(self, ritual_id: int) -> "Ritual.State":
        call = self._coordinator.method.getRitualState(ritual_id)
        state = await self._backend_session.eth_call(call)
        return Ritual.State(state)

    async def get_ritual_id_from_public_key(self, public_key: DkgPublicKey) -> int:
        pk_bytes = bytes(public_key)
        pk_word0 = pk_bytes[:32]
        pk_word1 = pk_bytes[32:]
        call = self._coordinator.method.getRitualIdFromPublicKey((pk_word0, pk_word1))
        ritual_id = await self._backend_session.eth_call(call)
        assert isinstance(ritual_id, int)
        return ritual_id

    async def initiate_ritual(
        self,
        signer: Signer,
        providers: Sequence[IdentityAddress],
        authority: IdentityAddress,
        duration: int,
        access_controller: IdentityAddress,
    ) -> int:
        call = self._coordinator.method.initiateRitual(
            providers, authority, duration, access_controller
        )
        event = self._coordinator.event.StartRitual
        events = await self._backend_session.transact(signer, call, return_events=[event])
        assert len(events[event]) == 1
        return cast(int, events[event][0]["ritualId"])


@frozen
class Ritual:
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

    @frozen
    class Participant:
        provider: IdentityAddress
        aggregated: bool
        transcript: Optional[Transcript]
        decryption_request_static_key: SessionStaticKey

    class State(Enum):
        NON_INITIATED = 0
        AWAITING_TRANSCRIPTS = 1
        AWAITING_AGGREGATIONS = 2
        TIMEOUT = 3
        INVALID = 4
        FINALIZED = 5
