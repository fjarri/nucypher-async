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

from web3 import Web3
from web3.providers import HTTPProvider
from web3.middleware import geth_poa_middleware

from .eth_account import EthAddress


class Registry:
    """
    Registry for Rinkeby.
    """
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/token/T.sol
    T = EthAddress.from_checksum('0xc3871E2C11Ff18d809Bce74d1e4229d561aa3F09')
    # https://github.com/threshold-network/solidity-contracts/blob/main/contracts/staking/TokenStaking.sol
    TOKEN_STAKING = EthAddress.from_checksum('0x18eFb520dA5D387982C860a64855C14C0AcADF3F')
    # https://github.com/nucypher/nucypher/blob/threshold-network/nucypher/blockchain/eth/sol/source/contracts/SimplePREApplication.sol
    PRE_APPLICATION = EthAddress.from_checksum('0xaE0d9D8edec5567BBFA8B5cbCD6705a13491Ca35')


ABI_DIR = Path(__file__).parent / 'eth_abi'

with open(ABI_DIR / 'T.json') as f:
    T_ABI = json.load(f)['abi']

with open(ABI_DIR / 'TokenStaking.json') as f:
    TOKEN_STAKING_ABI = json.load(f)['abi']

with open(ABI_DIR / 'SimplePREApplication.json') as f:
    PRE_APPLICATION_ABI = json.load(f)['abi']


class BaseEthClient:

    async def get_staker_address(self, operator_address: EthAddress):
        pass

    async def get_operator_address(self, staker_address: EthAddress):
        pass

    async def is_staker_authorized(self, staker_address: EthAddress):
        pass

    async def get_eth_balance(self, address: EthAddress):
        pass


class EthClient(BaseEthClient):

    @classmethod
    def from_http_endpoint(cls, url):
        provider = HTTPProvider(url)
        return cls(provider)

    def __init__(self, provider):
        self._web3 = Web3(provider=provider)
        self._web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        self._t = self._web3.eth.contract(Registry.T.to_checksum(), abi=T_ABI)
        self._token_staking = self._web3.eth.contract(Registry.TOKEN_STAKING.to_checksum(), abi=TOKEN_STAKING_ABI)
        self._pre_application = self._web3.eth.contract(Registry.PRE_APPLICATION.to_checksum(), abi=PRE_APPLICATION_ABI)

    async def _transact(self, contract_call):
        # TODO: this needs work, and testing. How do we test it?
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

    async def get_staked_amount(self, staker_address: EthAddress):
        t, keep_in_t, nu_in_t = self._token_staking.functions.stakes(bytes(staker_address)).call()
        return t + keep_in_t + nu_in_t # TODO: check that that's what we need

    async def get_staker_address(self, operator_address: EthAddress):
        return self._pre_application.functions.stakingProviderFromOperator(bytes(operator_address)).call()

    async def get_operator_address(self, staker_address: EthAddress):
        return self._pre_application.functions.getOperatorFromStakingProvider(bytes(staker_address)).call()

    async def is_staker_authorized(self, staker_address: EthAddress):
        return self._pre_application.functions.isAuthorized(bytes(staker_address)).call()

    async def get_eth_balance(self, address: EthAddress):
        return self._web3.eth.getBalance(bytes(address))
