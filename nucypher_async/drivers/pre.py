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
from eth_account.signers.local import LocalAccount
from ethereum_rpc import Address, Amount
from nucypher_core import HRAC, SessionStaticKey
from nucypher_core.ferveo import AggregatedTranscript, DkgPublicKey, Transcript
from pons import (
    AccountSigner,
    Client,
    ClientSession,
    ContractABI,
    DeployedContract,
    Event,
    Method,
    Mutability,
    Signer,
    abi,
)
from pons.http_provider import HTTPProvider

from ..domain import Domain
from .identity import IdentityAddress

# nucypher_contracts::SubscriptionManager.sol
_SUBSCRIPTION_MANAGER_ABI = ContractABI(
    methods=[
        Method(
            name="isPolicyActive",
            mutability=Mutability.VIEW,
            inputs=dict(_policyID=abi.bytes(16)),
            outputs=abi.bool,
        ),
        Method(
            name="getPolicyCost",
            mutability=Mutability.VIEW,
            inputs=dict(
                _size=abi.uint(16),
                _startTimestamp=abi.uint(32),
                _endTimestamp=abi.uint(32),
            ),
            outputs=abi.uint(256),
        ),
        Method(
            name="createPolicy",
            mutability=Mutability.PAYABLE,
            inputs=dict(
                _policyId=abi.bytes(16),
                _policyOwner=abi.address,
                _size=abi.uint(256),
                _startTimestamp=abi.uint(32),
                _endTimestamp=abi.uint(32),
            ),
        ),
    ],
)


class PREAddress(Address):
    pass


class BaseContracts:
    SUBSCRIPTION_MANAGER: PREAddress


class LynxContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0x0000000000000000000000000000000000000000")


class TapirContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0x0000000000000000000000000000000000000000")


class MainnetContracts(BaseContracts):
    """
    Registry for Polygon-Mainnet.
    """

    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0x0000000000000000000000000000000000000000")


class AmountMATIC(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} MATIC"


class PREAccount:
    @classmethod
    def random(cls) -> "PREAccount":
        return cls(Account.create())

    def __init__(self, account: LocalAccount):
        self._account = account
        self.address = PREAddress.from_hex(account.address)


class PREAccountSigner(AccountSigner):
    def __init__(self, account: PREAccount):
        super().__init__(account._account)

    @property
    def address(self) -> PREAddress:
        return PREAddress(bytes(super().address))


class PREClient:
    @classmethod
    def from_endpoint(cls, url: str, domain: Domain) -> "PREClient":
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

    @asynccontextmanager
    async def session(self) -> AsyncIterator["PREClientSession"]:
        async with self._client.session() as backend_session:
            yield PREClientSession(self, backend_session)


class PREClientSession:
    def __init__(self, client: PREClient, backend_session: ClientSession):
        self._client = client
        self._backend_session = backend_session
        self._contract = self._client._contract

    async def is_policy_active(self, hrac: HRAC) -> bool:
        is_active = await self._backend_session.call(
            self._contract.method.isPolicyActive(bytes(hrac))
        )
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(bool, is_active)

    async def get_policy_cost(self, shares: int, policy_start: int, policy_end: int) -> AmountMATIC:
        amount = await self._backend_session.call(
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
