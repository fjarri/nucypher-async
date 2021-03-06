from contextlib import asynccontextmanager
from collections import defaultdict

from pons import Address, Amount

from ..domain import Domain
from ..drivers.identity import IdentityClient, IdentityAddress, AmountT, AmountETH
from .eth import MockBackend, MockContract


class SimplePREApplication(MockContract):

    def __init__(self, abi):
        super().__init__(abi)
        self._min_stake = Amount.ether(40000)
        self._approved_staking_providers = {}
        self._stakes = {}
        self._staking_provider_to_operator = {}
        self._operator_to_staking_provider = {}
        self._confirmed_operators = set()

    def authorizedStake(self, staking_provider_address: Address) -> int:
        return self._stakes[staking_provider_address].as_wei()

    def stakingProviderFromOperator(self, operator_address: Address) -> Address:
        return self._operator_to_staking_provider[operator_address]

    def getOperatorFromStakingProvider(self, staking_provider_address: Address) -> Address:
        return self._staking_provider_to_operator[staking_provider_address]

    def isAuthorized(self, staking_provider_address: Address) -> bool:
        return staking_provider_address in self._stakes and self._stakes[staking_provider_address] >= self._min_stake

    def isOperatorConfirmed(self, operator_address: Address) -> bool:
        return operator_address in self._confirmed_operators

    def mock_set_up(self, staking_provider_address: Address, operator_address: Address, amount_t: AmountT):

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

    def __init__(self):
        mock_backend = MockBackend(AmountETH)
        super().__init__(mock_backend, Domain.MAINNET)

        self._mock_backend = mock_backend

        self._mock_pre_application = SimplePREApplication(self._pre_application.abi)
        mock_backend.mock_register_contract(self._pre_application.address, self._mock_pre_application)

    def mock_set_up(
            self,
            staking_provider_address: IdentityAddress,
            operator_address: IdentityAddress,
            amount_t: AmountT):
        """
        This essentially includes 4 operations:
        - approve T for staking (in the T contract)
        - stake (in the TokenStaking contract)
        - bond staking provider with operator (in the PREApplication contract)
        - confirm operator (in the PREApplication contract)
        Since we don't even T and TokenStaking functions in IdentityClient,
        for now this is merged into one big mock without a relation to contract functions.
        TODO: split into functions corresponding to the actual ABI.
        """
        # Clear out specific address and amount types at this boundary
        staking_provider_address = Address(bytes(staking_provider_address))
        operator_address = Address(bytes(operator_address))
        amount_t = Amount.wei(amount_t.as_wei())

        self._mock_pre_application.mock_set_up(staking_provider_address, operator_address, amount_t)
