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
import os
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from pons import HTTPProvider, Client, ContractABI, DeployedContract
from pons.types import Address, Amount


class IdentityAddress(Address):
    pass


class Registry:
    """
    Registry for Rinkeby.
    """
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/token/T.sol
    T = Address.from_hex('0xc3871E2C11Ff18d809Bce74d1e4229d561aa3F09')
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/staking/TokenStaking.sol
    TOKEN_STAKING = Address.from_hex('0x18eFb520dA5D387982C860a64855C14C0AcADF3F')
    # https://github.com/nucypher/nucypher/blob/threshold-network/nucypher/blockchain/eth/sol/source/contracts/SimplePREApplication.sol
    PRE_APPLICATION = Address.from_hex('0xaE0d9D8edec5567BBFA8B5cbCD6705a13491Ca35')


ABI_DIR = Path(__file__).parent / 'eth_abi'

with open(ABI_DIR / 'T.json') as f:
    T_ABI = json.load(f)['abi']

with open(ABI_DIR / 'TokenStaking.json') as f:
    TOKEN_STAKING_ABI = json.load(f)['abi']

with open(ABI_DIR / 'SimplePREApplication.json') as f:
    PRE_APPLICATION_ABI = json.load(f)['abi']


class IdentityAccount:

    @classmethod
    def from_payload(cls, payload, password):
        pk = Account.decrypt(payload, password)
        account = Account.from_key(pk)
        return cls(account)

    @classmethod
    def random(cls):
        return cls(Account.create())

    def __init__(self, account):
        self._account = account
        self.address = IdentityAddress.from_hex(account.address)

    def sign_message(self, message: bytes):
        signature = self._account.sign_message(encode_defunct(message))
        return to_standard_signature_bytes(signature.signature)


class AmountETH(Amount):

    def __repr__(self):
        return f"AmountETH({self.as_wei()})"

    def __str__(self):
        return f"{self.as_ether()} ETH"


class AmountT(Amount):

    def __repr__(self):
        return f"AmountT({self.as_wei()})"

    def __str__(self):
        return f"{self.as_ether()} T"


class BaseIdentityClient:

    async def get_staking_provider_address(self, operator_address: Address) -> Address:
        pass

    async def get_operator_address(self, staking_provider_address: Address) -> Address:
        pass

    async def is_staking_provider_authorized(self, staking_provider_address: Address) -> bool:
        pass

    async def get_eth_balance(self, address: Address) -> AmountETH:
        pass


class IdentityClient(BaseIdentityClient):

    @classmethod
    def from_http_endpoint(cls, url):
        provider = HTTPProvider(url)
        return cls(provider)

    def __init__(self, provider):
        self._client = Client(provider)

        self._t = DeployedContract(
            address=Registry.T, abi=ContractABI(T_ABI))
        self._token_staking = DeployedContract(
            address=Registry.TOKEN_STAKING, abi=ContractABI(TOKEN_STAKING_ABI))
        self._pre_application = DeployedContract(
            address=Registry.PRE_APPLICATION, abi=ContractABI(PRE_APPLICATION_ABI))

    """
    async def approve(self, staking_provider_address, t_amount_wei):
        call = self._t.functions.approve(Registry.TOKEN_STAKING, t_amount_wei)
        await self._transact(call)

    async def stake(self, staking_provider_address, t_amount_wei):
        call = self._token_staking.functions.stake(staking_provider_address, staking_provider_address, staking_provider_address, t_amount_wei)
        await self._transact(call)

    async def bond(self, staking_provider_address, operator_address):
        call = self._pre_application.functions.bondOperator(staking_provider_address, operator_address)
        await self._transact(call)
    """

    async def get_staked_amount(self, staking_provider_address: Address) -> AmountT:
        t, keep_in_t, nu_in_t = await self._client.call(
            self._token_staking.address,
            self._token_staking.abi.stakes(bytes(staking_provider_address)))
        return AmountT(t + keep_in_t + nu_in_t) # TODO: check that that's what we need

    async def get_staking_provider_address(self, operator_address: Address) -> Address:
        address = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.stakingProviderFromOperator(bytes(operator_address)))
        return Address.from_hex(address)

    async def get_operator_address(self, staking_provider_address: Address) -> Address:
        address = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.getOperatorFromStakingProvider(bytes(staking_provider_address)))
        return Address.from_hex(address)

    async def is_staking_provider_authorized(self, staking_provider_address: Address):
        result = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.isAuthorized(bytes(staking_provider_address)))
        assert isinstance(result, bool)
        return result

    async def is_operator_confirmed(self, operator_address: Address):
        result = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.isOperatorConfirmed(bytes(operator_address)))
        assert isinstance(result, bool)
        return result

    async def get_balance(self, address: Address) -> AmountETH:
        amount = await self._client.get_balance(address)
        return AmountETH(amount.as_wei())
