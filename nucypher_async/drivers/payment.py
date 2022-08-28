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
import json
from pathlib import Path
from typing import Type, AsyncIterator, cast

from eth_account import Account
from eth_account.signers.base import BaseAccount

from nucypher_core import HRAC
from pons import (
    HTTPProvider,
    Client,
    ContractABI,
    DeployedContract,
    Signer,
    AccountSigner,
    ReadMethod,
    WriteMethod,
    Address,
    Amount,
    abi,
)
from pons._client import ClientSession

from ..domain import Domain


_SUBSCRIPTION_MANAGER_ABI = ContractABI(
    read=[
        ReadMethod(
            name="isPolicyActive",
            inputs=dict(_policyID=abi.bytes(16)),
            outputs=abi.bool,
        ),
        ReadMethod(
            name="getPolicyCost",
            inputs=dict(
                _size=abi.uint(16),
                _startTimestamp=abi.uint(32),
                _endTimestamp=abi.uint(32),
            ),
            outputs=abi.uint(256),
        ),
    ],
    write=[
        WriteMethod(
            name="createPolicy",
            inputs=dict(
                _policyId=abi.bytes(16),
                _policyOwner=abi.address,
                _size=abi.uint(256),
                _startTimestamp=abi.uint(32),
                _endTimestamp=abi.uint(32),
            ),
        )
    ],
)


class PaymentAddress(Address):
    pass


class BaseContracts:
    SUBSCRIPTION_MANAGER: PaymentAddress


class IbexContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class OryxContracts(BaseContracts):
    """
    Registry for Polygon-Mumbai.
    """

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex("0xb9015d7b35ce7c81dde38ef7136baa3b1044f313")


class MainnetContracts(BaseContracts):
    """
    Registry for Polygon-Mainnet.
    """

    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex("0xB0194073421192F6Cf38d72c791Be8729721A0b3")


class AmountMATIC(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} MATIC"


class PaymentAccount:
    @classmethod
    def random(cls) -> "PaymentAccount":
        return cls(Account.create())

    def __init__(self, account: BaseAccount):
        self._account = account
        self.address = PaymentAddress.from_hex(account.address)


class PaymentAccountSigner(AccountSigner):
    def __init__(self, payment_account: PaymentAccount):
        super().__init__(payment_account._account)

    @property
    def address(self) -> PaymentAddress:
        return PaymentAddress(bytes(super().address))


class PaymentClient:
    @classmethod
    def from_endpoint(cls, url: str, domain: Domain) -> "PaymentClient":
        assert url.startswith("https://")
        provider = HTTPProvider(url)
        client = Client(provider)
        return cls(client, domain)

    def __init__(self, backend_client: Client, domain: Domain):
        self._client = backend_client

        registry: Type[BaseContracts]
        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.IBEX:
            registry = IbexContracts
        elif domain == Domain.ORYX:
            registry = OryxContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._manager = DeployedContract(
            address=registry.SUBSCRIPTION_MANAGER, abi=_SUBSCRIPTION_MANAGER_ABI
        )

    @asynccontextmanager
    async def session(self) -> AsyncIterator["PaymentClientSession"]:
        async with self._client.session() as backend_session:
            yield PaymentClientSession(self, backend_session)


class PaymentClientSession:
    def __init__(self, payment_client: PaymentClient, backend_session: ClientSession):
        self._payment_client = payment_client
        self._backend_session = backend_session
        self._manager = self._payment_client._manager

    async def is_policy_active(self, hrac: HRAC) -> bool:
        is_active = await self._backend_session.eth_call(
            self._manager.read.isPolicyActive(bytes(hrac))
        )
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(bool, is_active)

    async def get_policy_cost(self, shares: int, policy_start: int, policy_end: int) -> AmountMATIC:
        amount = await self._backend_session.eth_call(
            self._manager.read.getPolicyCost(shares, policy_start, policy_end)
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
        call = self._manager.write.createPolicy(
            bytes(hrac), signer.address, shares, policy_start, policy_end
        )
        await self._backend_session.transact(signer, call, amount=amount)
