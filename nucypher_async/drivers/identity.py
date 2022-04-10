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
import os
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account._utils.signing import to_standard_signature_bytes

from pons import HTTPProvider, Client, ContractABI, DeployedContract, Address, Amount

from ..domain import Domain


class IdentityAddress(Address):

    def __repr__(self):
        return f"IdentityAddress.from_hex({self.as_checksum()})"


class IbexContracts:
    """
    Registry for Rinkeby.
    """
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/token/T.sol
    T = IdentityAddress.from_hex('0xc3871E2C11Ff18d809Bce74d1e4229d561aa3F09')
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/staking/TokenStaking.sol
    TOKEN_STAKING = IdentityAddress.from_hex('0x18eFb520dA5D387982C860a64855C14C0AcADF3F')
    # https://github.com/nucypher/nucypher/blob/threshold-network/nucypher/blockchain/eth/sol/source/contracts/SimplePREApplication.sol
    PRE_APPLICATION = IdentityAddress.from_hex('0xaE0d9D8edec5567BBFA8B5cbCD6705a13491Ca35')


class MainnetContracts:
    """
    Registry for mainnet.
    """
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/token/T.sol
    T = IdentityAddress.from_hex('0xCdF7028ceAB81fA0C6971208e83fa7872994beE5')
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/staking/TokenStaking.sol
    TOKEN_STAKING = IdentityAddress.from_hex('0x01b67b1194c75264d06f808a921228a95c765dd7')
    # https://github.com/nucypher/nucypher/blob/threshold-network/nucypher/blockchain/eth/sol/source/contracts/SimplePREApplication.sol
    PRE_APPLICATION = IdentityAddress.from_hex('0x7E01c9c03FD3737294dbD7630a34845B0F70E5Dd')


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


class IdentityClient:

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
        else:
            raise ValueError(f"Unknown domain: {domain}")

        self._t = DeployedContract(
            address=registry.T, abi=ContractABI(T_ABI))
        self._token_staking = DeployedContract(
            address=registry.TOKEN_STAKING, abi=ContractABI(TOKEN_STAKING_ABI))
        self._pre_application = DeployedContract(
            address=registry.PRE_APPLICATION, abi=ContractABI(PRE_APPLICATION_ABI))

    @asynccontextmanager
    async def session(self):
        async with self._client.session() as backend_session:
            yield IdentityClientSession(self, backend_session)


class IdentityClientSession:

    def __init__(self, identity_client, backend_session):
        self._identity_client = identity_client
        self._backend_session = backend_session

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

    async def get_staked_amount(self, staking_provider_address: IdentityAddress) -> AmountT:
        t, keep_in_t, nu_in_t = await self._backend_session.call(
            self._identity_client._token_staking.address,
            self._identity_client._token_staking.abi.stakes(bytes(staking_provider_address)))
        return AmountT(t + keep_in_t + nu_in_t)

    async def get_staking_provider_address(self, operator_address: IdentityAddress) -> IdentityAddress:
        address = await self._backend_session.call(
            self._identity_client._pre_application.address,
            self._identity_client._pre_application.abi.stakingProviderFromOperator(bytes(operator_address)))
        return IdentityAddress.from_hex(address)

    async def get_operator_address(self, staking_provider_address: IdentityAddress) -> IdentityAddress:
        address = await self._backend_session.call(
            self._identity_client._pre_application.address,
            self._identity_client._pre_application.abi.getOperatorFromStakingProvider(bytes(staking_provider_address)))
        return IdentityAddress.from_hex(address)

    async def is_staking_provider_authorized(self, staking_provider_address: IdentityAddress):
        result = await self._backend_session.call(
            self._identity_client._pre_application.address,
            self._identity_client._pre_application.abi.isAuthorized(bytes(staking_provider_address)))
        assert isinstance(result, bool)
        return result

    async def is_operator_confirmed(self, operator_address: IdentityAddress):
        result = await self._backend_session.call(
            self._identity_client._pre_application.address,
            self._identity_client._pre_application.abi.isOperatorConfirmed(bytes(operator_address)))
        assert isinstance(result, bool)
        return result

    async def get_balance(self, address: IdentityAddress) -> AmountETH:
        amount = await self._backend_session.get_balance(address)
        return AmountETH(amount.as_wei())
