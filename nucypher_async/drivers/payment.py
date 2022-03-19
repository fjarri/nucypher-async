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

import json
from pathlib import Path

from eth_account import Account

from nucypher_core import HRAC
from pons import HTTPProvider, Client, ContractABI, DeployedContract
from pons.types import Address, Amount


class Registry:
    """
    Registry for Mumbai.
    """
    # https://github.com/nucypher/nucypher-contracts/blob/main/contracts/matic/SubscriptionManager.sol
    SUBSCRIPTION_MANAGER = Address.from_hex('0xb9015d7b35ce7c81dde38ef7136baa3b1044f313')


ABI_DIR = Path(__file__).parent / 'eth_abi'

with open(ABI_DIR / 'SubscriptionManager.json') as f:
    SUBSCRIPTION_MANAGER_ABI = json.load(f)['abi']


class PaymentAddress(Address):
    pass


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


class BasePaymentClient:

    async def is_policy_active(self, hrac: HRAC) -> bool:
        pass

    async def create_policy(self, hrac: HRAC, shares: int, policy_start: int, policy_end: int):
        pass


class PaymentClient(BasePaymentClient):

    @classmethod
    def from_http_endpoint(cls, url):
        provider = HTTPProvider(url)
        return cls(provider)

    def __init__(self, provider):
        self._client = Client(provider)

        self._manager = DeployedContract(
            address=Registry.SUBSCRIPTION_MANAGER, abi=ContractABI(SUBSCRIPTION_MANAGER_ABI))

    async def is_policy_active(self, hrac: HRAC) -> bool:
        return await self._client.call(self._manager.address, self._manager.abi.isPolicyActive(bytes(hrac)))

    def with_signer(self, signer):
        return SigningPaymentClient(self, signer)


class SigningPaymentClient:

    def __init__(self, client, signer):
        self._client = client._client.with_signer(signer)
        self._manager = client._manager
        self._signer = signer

    async def create_policy(self, hrac: HRAC, shares: int, policy_start: int, policy_end: int):
        value = await self._client.call(
            self._manager.address,
            self._manager.abi.getPolicyCost(shares, policy_start, policy_end))
        value = AmountMATIC.wei(value)
        print("Policy cost", value)
        print("Policy:", policy_start, policy_end)
        call = self._manager.abi.createPolicy(
            bytes(hrac),
            bytes(self._signer.address()),
            shares,
            policy_start,
            policy_end)
        await self._client.transact(self._manager.address, call, value=value)
