from contextlib import asynccontextmanager
from collections import defaultdict

from pons import MethodCall

from ..domain import Domain
from ..drivers.identity import IdentityClient, IdentityAddress, AmountT, AmountETH


class MockBackend():

    def __init__(self):
        self._min_stake = AmountT.ether(40000)
        self._approved_staking_providers = {}
        self._stakes = {}
        self._staking_provider_to_operator = {}
        self._operator_to_staking_provider = {}
        self._confirmed_operators = set()
        self._balances = defaultdict(lambda: AmountETH(0))

    @asynccontextmanager
    async def session(self):
        yield self

    # Administrative methods to modify the mocked state

    def approve(self, staking_provider_address: IdentityAddress, amount_t: AmountT):
        assert staking_provider_address not in self._approved_staking_providers
        self._approved_staking_providers[staking_provider_address] = amount_t

    def stake(self, staking_provider_address: IdentityAddress, amount_t: AmountT):
        assert staking_provider_address in self._approved_staking_providers
        assert self._approved_staking_providers[staking_provider_address] >= amount_t
        assert staking_provider_address not in self._stakes
        self._stakes[staking_provider_address] = amount_t

    def bond_operator(self, staking_provider_address: IdentityAddress, operator_address: IdentityAddress):
        assert staking_provider_address not in self._staking_provider_to_operator
        assert operator_address not in self._operator_to_staking_provider
        self._staking_provider_to_operator[staking_provider_address] = operator_address
        self._operator_to_staking_provider[operator_address] = staking_provider_address

    def confirm_operator(self, operator_address: IdentityAddress):
        assert operator_address not in self._confirmed_operators
        self._confirmed_operators.add(operator_address)

    def set_balance(self, address: IdentityAddress, amount: AmountETH):
        self._balances[address] = amount

    # Mocked contract methods (arguments are whatever MethodCall packs)

    def _call_authorized_stake(self, staking_provider_address: bytes) -> int:
        return self._stakes[IdentityAddress(staking_provider_address)].as_wei()

    def _call_staking_provider_from_operator(self, operator_address: bytes) -> str:
        return self._operator_to_staking_provider[IdentityAddress(operator_address)].as_checksum()

    def _call_get_operator_from_staking_provider(self, staking_provider_address: bytes) -> str:
        return self._staking_provider_to_operator[IdentityAddress(staking_provider_address)].as_checksum()

    def _call_is_authorized(self, staking_provider_address: bytes) -> bool:
        address = IdentityAddress(staking_provider_address)
        return address in self._stakes and self._stakes[address] >= self._min_stake

    def _call_is_operator_confirmed(self, operator_address: bytes) -> bool:
        return IdentityAddress(operator_address) in self._confirmed_operators

    # Mocked ``pons.Client`` methods

    async def call(self, contract_address: IdentityAddress, contract_call: MethodCall):
        # TODO: check that the address is correct (that is, the correct registry was used)
        dispatch = dict(
            authorizedStake=self._call_authorized_stake,
            stakingProviderFromOperator=self._call_staking_provider_from_operator,
            getOperatorFromStakingProvider=self._call_get_operator_from_staking_provider,
            isAuthorized=self._call_is_authorized,
            isOperatorConfirmed=self._call_is_operator_confirmed,
            )
        return dispatch[contract_call.method_name](*contract_call.args)

    async def get_balance(self, address: IdentityAddress) -> AmountETH:
        return self._balances[address]


class MockIdentityClient(IdentityClient):

    def __init__(self):
        mock_backend = MockBackend()
        super().__init__(mock_backend, Domain.MAINNET)
        self._mock_backend = mock_backend

    def mock_approve(self, staking_provider_address: IdentityAddress, amount_t: AmountT):
        self._mock_backend.approve(staking_provider_address, amount_t)

    def mock_stake(self, staking_provider_address: IdentityAddress, amount_t: AmountT):
        self._mock_backend.stake(staking_provider_address, amount_t)

    def mock_bond_operator(self, staking_provider_address: IdentityAddress, operator_address: IdentityAddress):
        self._mock_backend.bond_operator(staking_provider_address, operator_address)

    def mock_confirm_operator(self, operator_address: IdentityAddress):
        self._mock_backend.confirm_operator(operator_address)
