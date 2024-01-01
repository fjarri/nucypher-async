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
from typing import AsyncIterator, Dict, Type, cast

from eth_account import Account
from eth_account._utils.signing import to_standard_signature_bytes
from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount
from pons import (
    Address,
    Amount,
    Client,
    ClientSession,
    ContractABI,
    DeployedContract,
    HTTPProvider,
    Method,
    Mutability,
    abi,
)

from ..domain import Domain

# nucypher_contracts::TACoApplication.sol
_TACO_APP_ABI = ContractABI(
    methods=[
        Method(
            name="authorizedStake",
            mutability=Mutability.VIEW,
            inputs=dict(_stakingProvider=abi.address),
            outputs=abi.uint(96),
        ),
        Method(
            name="operatorToStakingProvider",
            mutability=Mutability.VIEW,
            inputs=dict(_operator=abi.address),
            outputs=abi.address,
        ),
        Method(
            name="stakingProviderToOperator",
            mutability=Mutability.VIEW,
            inputs=dict(_stakingProvider=abi.address),
            outputs=abi.address,
        ),
        Method(
            name="isAuthorized",
            mutability=Mutability.VIEW,
            inputs=dict(_stakingProvider=abi.address),
            outputs=abi.bool,
        ),
        Method(
            name="isOperatorConfirmed",
            mutability=Mutability.VIEW,
            inputs=dict(_operator=abi.address),
            outputs=abi.bool,
        ),
        Method(
            name="getActiveStakingProviders",
            mutability=Mutability.VIEW,
            inputs=dict(_start_index=abi.uint(256), _maxStakingProviders=abi.uint(256)),
            outputs=[abi.uint(256), abi.uint(256)[2][...]],
        ),
    ]
)


class IdentityAddress(Address):
    pass


class BaseContracts:
    TACO_APPLICATION: IdentityAddress


class LynxContracts(BaseContracts):
    """
    Registry for Lynx on Goerli.
    """

    TACO_APPLICATION = IdentityAddress.from_hex("0x0000000000000000000000000000000000000000")


class TapirContracts(BaseContracts):
    """
    Registry for Tapir on Goerli.
    """

    TACO_APPLICATION = IdentityAddress.from_hex("0x0000000000000000000000000000000000000000")


class MainnetContracts(BaseContracts):
    """
    Registry for mainnet.
    """

    TACO_APPLICATION = IdentityAddress.from_hex("0x0000000000000000000000000000000000000000")


class IdentityAccount:
    @classmethod
    def from_payload(cls, payload: str, password: str) -> "IdentityAccount":
        private_key = Account.decrypt(payload, password)
        account = Account.from_key(private_key)
        return cls(account)

    @classmethod
    def random(cls) -> "IdentityAccount":
        return cls(Account.create())

    def __init__(self, account: BaseAccount):
        self._account = account
        self.address = IdentityAddress.from_hex(account.address)

    def sign_message(self, message: bytes) -> bytes:
        signature = self._account.sign_message(encode_defunct(message))
        return to_standard_signature_bytes(signature.signature)


class AmountETH(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} ETH"


class AmountT(Amount):
    def __str__(self) -> str:
        return f"{self.as_ether()} T"


class IdentityClient:
    @classmethod
    def from_endpoint(cls, url: str, domain: Domain) -> "IdentityClient":
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

        self._contract = DeployedContract(address=registry.TACO_APPLICATION, abi=_TACO_APP_ABI)

    @asynccontextmanager
    async def session(self) -> AsyncIterator["IdentityClientSession"]:
        async with self._client.session() as backend_session:
            yield IdentityClientSession(self, backend_session)


class IdentityClientSession:
    def __init__(self, client: IdentityClient, backend_session: ClientSession):
        self._client = client
        self._backend_session = backend_session
        self._contract = client._contract

    async def get_staked_amount(self, staking_provider_address: IdentityAddress) -> AmountT:
        staked_amount = await self._backend_session.eth_call(
            self._contract.method.authorizedStake(staking_provider_address)
        )
        return AmountT.wei(staked_amount)

    async def get_staking_provider_address(
        self, operator_address: IdentityAddress
    ) -> IdentityAddress:
        address = await self._backend_session.eth_call(
            self._contract.method.operatorToStakingProvider(operator_address)
        )
        return IdentityAddress(bytes(address))

    async def get_operator_address(
        self, staking_provider_address: IdentityAddress
    ) -> IdentityAddress:
        address = await self._backend_session.eth_call(
            self._contract.method.stakingProviderToOperator(staking_provider_address)
        )
        return IdentityAddress(bytes(address))

    async def is_staking_provider_authorized(
        self, staking_provider_address: IdentityAddress
    ) -> bool:
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(
            bool,
            await self._backend_session.eth_call(
                self._contract.method.isAuthorized(staking_provider_address)
            ),
        )

    async def is_operator_confirmed(self, operator_address: IdentityAddress) -> bool:
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(
            bool,
            await self._backend_session.eth_call(
                self._contract.method.isOperatorConfirmed(operator_address)
            ),
        )

    async def get_balance(self, address: IdentityAddress) -> AmountETH:
        amount = await self._backend_session.eth_get_balance(address)
        return AmountETH.wei(amount.as_wei())

    async def get_active_staking_providers(
        self, start_index: int = 0, max_staking_providers: int = 0
    ) -> Dict[IdentityAddress, AmountT]:
        # TODO: implement pagination
        _total_staked, staking_providers_data = await self._backend_session.eth_call(
            self._contract.method.getActiveStakingProviders(start_index, max_staking_providers)
        )
        staking_providers = {
            IdentityAddress(address.to_bytes(20, byteorder="big")): AmountT.wei(amount)
            for address, amount in staking_providers_data
        }

        return staking_providers
