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
    Error,
    HTTPProvider,
    Method,
    Mutability,
    Provider,
    Signer,
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
        Method(
            name="bondOperator",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(_stakingProvider=abi.address, _operator=abi.address),
        ),
    ],
    errors=[Error(name="MyError", fields=dict(_stakingProvider=abi.address, sender=abi.address))],
)

_STAKING_ABI = ContractABI(
    methods=[
        Method(
            name="setRoles",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(_stakingProvider=abi.address),
        ),
        Method(
            name="setStakes",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(
                _stakingProvider=abi.address,
                _tStake=abi.uint(96),
                _keepInTStake=abi.uint(96),
                _nuInTStake=abi.uint(96),
            ),
        ),
        Method(
            name="authorizationIncreased",
            mutability=Mutability.NONPAYABLE,
            inputs=dict(
                _stakingProvider=abi.address,
                _fromAmount=abi.uint(96),
                _toAmount=abi.uint(96),
            ),
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

        registry: Type[BaseContracts]
        if domain == Domain.MAINNET:
            registry = MainnetContracts
        elif domain == Domain.LYNX:
            registry = LynxContracts
        elif domain == Domain.TAPIR:
            registry = TapirContracts
        else:
            raise ValueError(f"Unknown domain: {domain}")

        return cls(provider, registry.TACO_APPLICATION, registry.TACO_APPLICATION)

    def __init__(
        self, provider: Provider, taco_application_address: Address, staking_address: Address
    ):
        # TODO: or should we take `DeployedContract`
        # and assert that _TACO_APP_ABI is compatible with it?
        self._client = Client(provider)
        self._app = DeployedContract(address=taco_application_address, abi=_TACO_APP_ABI)
        self._staking = DeployedContract(address=staking_address, abi=_STAKING_ABI)

    @asynccontextmanager
    async def session(self) -> AsyncIterator["IdentityClientSession"]:
        async with self._client.session() as backend_session:
            yield IdentityClientSession(self, backend_session)


class IdentityClientSession:
    def __init__(self, client: IdentityClient, backend_session: ClientSession):
        self._client = client
        self._backend_session = backend_session
        self._app = client._app
        self._staking = client._staking

    async def get_staked_amount(self, staking_provider_address: IdentityAddress) -> AmountT:
        staked_amount = await self._backend_session.eth_call(
            self._app.method.authorizedStake(staking_provider_address)
        )
        return AmountT.wei(staked_amount)

    async def get_staking_provider_address(
        self, operator_address: IdentityAddress
    ) -> IdentityAddress:
        address = await self._backend_session.eth_call(
            self._app.method.operatorToStakingProvider(operator_address)
        )
        return IdentityAddress(bytes(address))

    async def get_operator_address(
        self, staking_provider_address: IdentityAddress
    ) -> IdentityAddress:
        address = await self._backend_session.eth_call(
            self._app.method.stakingProviderToOperator(staking_provider_address)
        )
        return IdentityAddress(bytes(address))

    async def is_staking_provider_authorized(
        self, staking_provider_address: IdentityAddress
    ) -> bool:
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(
            bool,
            await self._backend_session.eth_call(
                self._app.method.isAuthorized(staking_provider_address)
            ),
        )

    async def is_operator_confirmed(self, operator_address: IdentityAddress) -> bool:
        # TODO: casting for now, see https://github.com/fjarri/pons/issues/41
        return cast(
            bool,
            await self._backend_session.eth_call(
                self._app.method.isOperatorConfirmed(operator_address)
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
            self._app.method.getActiveStakingProviders(start_index, max_staking_providers)
        )
        staking_providers = {
            IdentityAddress(address.to_bytes(20, byteorder="big")): AmountT.wei(amount)
            for address, amount in staking_providers_data
        }

        return staking_providers

    async def add_staking_provider(
        self,
        owner_signer: Signer,
        staking_provider_signer: Signer,
        operator_address: IdentityAddress,
        stake: AmountT,
    ):
        staking_provider_address = staking_provider_signer.address

        # TODO: this only applies to testnet staking. How do we make it general? Or move it to tests?
        await self._backend_session.transact(
            owner_signer, self._staking.method.setRoles(_stakingProvider=staking_provider_address)
        )
        await self._backend_session.transact(
            owner_signer,
            self._staking.method.setStakes(
                _stakingProvider=staking_provider_address,
                _tStake=stake.as_wei(),
                _keepInTStake=0,
                _nuInTStake=0,
            ),
        )
        await self._backend_session.transact(
            owner_signer,
            self._staking.method.authorizationIncreased(
                _stakingProvider=staking_provider_address, _fromAmount=0, _toAmount=stake.as_wei()
            ),
        )
        await self._backend_session.transact(
            staking_provider_signer,
            self._app.method.bondOperator(
                _stakingProvider=staking_provider_address, _operator=operator_address
            ),
        )
