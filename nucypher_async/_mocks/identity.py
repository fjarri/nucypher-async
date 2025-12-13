from typing import cast

from ethereum_rpc import Address, Amount
from pons import Client, ContractABI

from ..blockchain.identity import AmountT, IdentityAddress, IdentityClient
from ..domain import Domain
from .eth import MockBackend, MockContract


class TacoApplication(MockContract):
    def __init__(self, abi: ContractABI):
        super().__init__(abi)
        self._min_stake = Amount.ether(40000)
        self._approved_staking_providers: dict[Address, Amount] = {}
        self._stakes: dict[Address, Amount] = {}
        self._staking_provider_to_operator: dict[Address, Address] = {}
        self._operator_to_staking_provider: dict[Address, Address] = {}
        self._confirmed_operators: set[Address] = set()

    def authorizedStake(self, staking_provider_address: Address) -> int:  # noqa: N802
        return self._stakes[staking_provider_address].as_wei()

    def operatorToStakingProvider(self, operator_address: Address) -> Address:  # noqa: N802
        return self._operator_to_staking_provider[operator_address]

    def stakingProviderToOperator(self, staking_provider_address: Address) -> Address:  # noqa: N802
        return self._staking_provider_to_operator[staking_provider_address]

    def isAuthorized(self, staking_provider_address: Address) -> bool:  # noqa: N802
        return (
            staking_provider_address in self._stakes
            and self._stakes[staking_provider_address] >= self._min_stake
        )

    def isOperatorConfirmed(self, operator_address: Address) -> bool:  # noqa: N802
        return operator_address in self._confirmed_operators

    def getActiveStakingProviders(  # noqa: N802
        self, _start_index: int, _max_staking_providers: int
    ) -> tuple[int, list[bytes]]:
        # TODO (#47): implement pagination
        total = sum(amount.as_wei() for amount in self._stakes.values())
        return total, [
            bytes(address) + amount.as_wei().to_bytes(12, byteorder="big")
            for address, amount in self._stakes.items()
        ]

    def mock_set_up(
        self,
        staking_provider_address: Address,
        operator_address: Address,
        amount_t: Amount,
    ) -> None:
        # Approve stake
        assert staking_provider_address not in self._approved_staking_providers
        self._approved_staking_providers[staking_provider_address] = amount_t

        # Stake
        assert staking_provider_address in self._approved_staking_providers
        assert self._approved_staking_providers[staking_provider_address] >= amount_t
        assert staking_provider_address not in self._stakes
        self._stakes[staking_provider_address] = amount_t

        # Bond staking provider and operator
        assert staking_provider_address not in self._staking_provider_to_operator
        assert operator_address not in self._operator_to_staking_provider
        self._staking_provider_to_operator[staking_provider_address] = operator_address
        self._operator_to_staking_provider[operator_address] = staking_provider_address

        # Confirm operator
        assert operator_address not in self._confirmed_operators
        self._confirmed_operators.add(operator_address)


class MockIdentityClient(IdentityClient):
    def __init__(self) -> None:
        mock_backend = MockBackend()
        super().__init__(cast("Client", mock_backend), Domain.MAINNET)

        self._mock_backend = mock_backend

        self._mock_taco_application = TacoApplication(self._taco_application.abi)
        mock_backend.mock_register_contract(
            self._taco_application.address, self._mock_taco_application
        )

    def mock_set_up(
        self,
        staking_provider_address: IdentityAddress,
        operator_address: IdentityAddress,
        amount_t: AmountT,
    ) -> None:
        """
        Includes 4 operations:
        - approve T for staking (in the T contract)
        - stake (in the TokenStaking contract)
        - bond staking provider with operator (in the PREApplication contract)
        - confirm operator (in the PREApplication contract)
        Since we don't even T and TokenStaking functions in IdentityClient,
        for now this is merged into one big mock without a relation to contract functions.
        TODO: split into functions corresponding to the actual ABI.
        """
        # Clear out specific address and amount types at this boundary
        staking_provider_address_ = Address(bytes(staking_provider_address))
        operator_address_ = Address(bytes(operator_address))
        amount_t_ = Amount.wei(amount_t.as_wei())

        self._mock_taco_application.mock_set_up(
            staking_provider_address_, operator_address_, amount_t_
        )
