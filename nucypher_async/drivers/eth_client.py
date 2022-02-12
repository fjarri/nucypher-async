from web3.providers import HTTPProvider

from .eth_account import EthAddress


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

    def __init__(self, provider):
        self.provider = provider

    async def get_staker_address(self, operator_address: EthAddress):
        pass

    async def get_operator_address(self, staker_address: EthAddress):
        pass

    async def is_staker_authorized(self, staker_address: EthAddress):
        pass

    async def get_eth_balance(self, address: EthAddress):
        pass
