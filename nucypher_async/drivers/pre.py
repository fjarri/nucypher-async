"""
A rough draft of the Eth driver.

Todo:
- finish up registries properly (include ABIs in the registry class,
  merge ABIs with contract addresses, add registries for different networks)
- find a way to get ABIs automatically
- find a way to test transactions
- set gas value properly (estimate gas, gas strategies)
- add newtypes for currencies instead of just using wei

"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from eth_account import Account
from eth_account.signers.local import LocalAccount
from ethereum_rpc import Address, Amount
from nucypher_core import HRAC
from pons import (
    AccountSigner,
    Client,
    ClientSession,
    ContractABI,
    DeployedContract,
    Method,
    Mutability,
    Signer,
    abi,
)
from pons.http_provider import HTTPProvider

from ..domain import Domain

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
    """Registry for Polygon-Mumbai."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class TapirContracts(BaseContracts):
    """Registry for Polygon-Mumbai."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class MainnetContracts(BaseContracts):
    """Registry for Polygon-Mainnet."""

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PREAddress.from_hex("0xB0194073421192F6Cf38d72c791Be8729721A0b3")


class PREAmount(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} PRE"


class PREAccount:
    @classmethod
    def random(cls) -> "PREAccount":
        return cls(Account.create())

    def __init__(self, account: LocalAccount):
        self._account = account
        self.address = PREAddress.from_hex(account.address)


class PREAccountSigner(AccountSigner):
    def __init__(self, pre_account: PREAccount):
        super().__init__(pre_account._account)  # noqa: SLF001

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

        registry: type[BaseContracts]
        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.LYNX:
            registry = LynxContracts
        elif domain == Domain.TAPIR:
            registry = TapirContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._manager = DeployedContract(
            address=registry.SUBSCRIPTION_MANAGER, abi=_SUBSCRIPTION_MANAGER_ABI
        )

    @asynccontextmanager
    async def session(self) -> AsyncIterator["PREClientSession"]:
        async with self._client.session() as backend_session:
            yield PREClientSession(self, backend_session)


class PREClientSession:
    def __init__(self, pre_client: PREClient, backend_session: ClientSession):
        self._pre_client = pre_client
        self._backend_session = backend_session
        self._manager = self._pre_client._manager  # noqa: SLF001

    async def is_policy_active(self, hrac: HRAC) -> bool:
        is_active = await self._backend_session.call(
            self._manager.method.isPolicyActive(bytes(hrac))
        )
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast("bool", is_active)

    async def get_policy_cost(self, shares: int, policy_start: int, policy_end: int) -> PREAmount:
        amount = await self._backend_session.call(
            self._manager.method.getPolicyCost(shares, policy_start, policy_end)
        )
        return PREAmount.wei(amount)

    async def create_policy(
        self,
        signer: Signer,
        hrac: HRAC,
        shares: int,
        policy_start: int,
        policy_end: int,
    ) -> None:
        amount = await self.get_policy_cost(shares, policy_start, policy_end)
        call = self._manager.method.createPolicy(
            bytes(hrac), signer.address, shares, policy_start, policy_end
        )
        await self._backend_session.transact(signer, call, amount=amount)
