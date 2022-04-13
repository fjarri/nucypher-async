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

from eth_account import Account

from nucypher_core import HRAC
from pons import HTTPProvider, Client, ContractABI, DeployedContract, Signer, AccountSigner
from pons.types import Address, Amount

from ..domain import Domain


class PaymentAddress(Address):
    pass


class IbexContracts:
    """
    Registry for Polygon-Mumbai.
    """
    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex('0xb9015d7b35ce7c81dde38ef7136baa3b1044f313')


class OryxContracts:
    """
    Registry for Polygon-Mumbai.
    """
    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex('0xb9015d7b35ce7c81dde38ef7136baa3b1044f313')


class MainnetContracts:
    """
    Registry for Polygon-Mainnet.
    """
    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = PaymentAddress.from_hex('0xB0194073421192F6Cf38d72c791Be8729721A0b3')


ABI_DIR = Path(__file__).parent / 'eth_abi'

with open(ABI_DIR / 'SubscriptionManager.json') as f:
    SUBSCRIPTION_MANAGER_ABI = json.load(f)['abi']


class AmountMATIC(Amount):

    def __repr__(self):
        return f"AmountMATIC({self.as_wei()})"

    def __str__(self):
        return f"{self.as_ether()} MATIC"


class PaymentAccount:

    @classmethod
    def random(cls):
        return cls(Account.create())

    def __init__(self, account):
        self._account = account
        self.address = PaymentAddress.from_hex(account.address)


class PaymentAccountSigner(AccountSigner):

    def __init__(self, payment_account: PaymentAccount):
        super().__init__(payment_account._account)

    @property
    def address(self):
        return PaymentAddress(bytes(super().address))


class PaymentClient:

    @classmethod
    def from_endpoint(cls, url, domain):
        assert url.startswith('https://')
        provider = HTTPProvider(url)
        client = Client(provider)
        return cls(client, domain)

    def __init__(self, backend_client, domain):
        self._client = backend_client

        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.IBEX:
            registry = IbexContracts
        elif domain == Domain.ORYX:
            registry = OryxContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._manager = DeployedContract(
            address=registry.SUBSCRIPTION_MANAGER, abi=ContractABI(SUBSCRIPTION_MANAGER_ABI))

    @asynccontextmanager
    async def session(self):
        async with self._client.session() as backend_session:
            yield PaymentClientSession(self, backend_session)


class PaymentClientSession:

    def __init__(self, payment_client, backend_session):
        self._payment_client = payment_client
        self._backend_session = backend_session

    async def is_policy_active(self, hrac: HRAC) -> bool:
        return await self._backend_session.call(
            self._payment_client._manager.address,
            self._payment_client._manager.abi.isPolicyActive(bytes(hrac)))

    async def get_policy_cost(self, shares: int, policy_start: int, policy_end: int) -> AmountMATIC:
        amount = await self._backend_session.call(
            self._payment_client._manager.address,
            self._payment_client._manager.abi.getPolicyCost(shares, policy_start, policy_end))
        return AmountMATIC.wei(amount)

    async def create_policy(self, signer: Signer, hrac: HRAC, shares: int, policy_start: int, policy_end: int):
        amount = await self.get_policy_cost(shares, policy_start, policy_end)
        call = self._payment_client._manager.abi.createPolicy(
            bytes(hrac),
            bytes(signer.address),
            shares,
            policy_start,
            policy_end)
        await self._backend_session.transact(signer, self._payment_client._manager.address, call, amount=amount)
