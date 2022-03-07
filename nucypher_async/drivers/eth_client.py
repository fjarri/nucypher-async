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

from pons import HTTPProvider, Client, ContractABI, DeployedContract
from pons.types import Address, Wei


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


class BaseEthClient:

    async def get_staker_address(self, operator_address: Address) -> Address:
        pass

    async def get_operator_address(self, staker_address: Address) -> Address:
        pass

    async def is_staker_authorized(self, staker_address: Address) -> bool:
        pass

    async def get_eth_balance(self, address: Address) -> Wei:
        pass


class EthClient(BaseEthClient):

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
    async def _transact(self, contract_call):
        # TODO: requires a signing client
        from_address = self._account.address
        nonce = self._web3.eth.get_transaction_count(from_address)
        call = contract_function(*args)
        tx = call.buildTransaction({'chainId': 4, 'gas': 1000000, 'nonce': nonce, 'from': from_address})
        signed_tx = w.eth.account.signTransaction(tx, self._account.pk_bytes)
        tx_hash = w.eth.send_raw_transaction(signed_tx.rawTransaction)
        # w.eth.wait_for_transaction_receipt(tx_hash)
        # or poll manually with get_transaction_receipt(), so this will be kinda async

    async def approve(self, staker_address, t_amount_wei):
        call = self._t.functions.approve(Registry.TOKEN_STAKING, t_amount_wei)
        await self._transact(call)

    async def stake(self, staker_address, t_amount_wei):
        call = self._token_staking.functions.stake(staker_address, staker_address, staker_address, t_amount_wei)
        await self._transact(call)

    async def bond(self, staker_address, operator_address):
        call = self._pre_application.functions.bondOperator(staker_address, operator_address)
        await self._transact(call)
    """

    async def get_staked_amount(self, staker_address: Address) -> int:
        t, keep_in_t, nu_in_t = await self._client.call(
            self._token_staking.address,
            self._token_staking.abi.stakes(bytes(staker_address)))
        return t + keep_in_t + nu_in_t # TODO: check that that's what we need

    async def get_staker_address(self, operator_address: Address) -> Address:
        address = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.stakingProviderFromOperator(bytes(operator_address)))
        return Address.from_hex(address)

    async def get_operator_address(self, staker_address: Address) -> Address:
        address = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.getOperatorFromStakingProvider(bytes(staker_address)))
        return Address.from_hex(address)

    async def is_staker_authorized(self, staker_address: Address):
        result = await self._client.call(
            self._pre_application.address,
            self._pre_application.abi.isAuthorized(bytes(staker_address)))
        assert isinstance(result, bool)
        return result

    async def get_eth_balance(self, address: Address) -> Wei:
        return await self._client.get_balance(address)
