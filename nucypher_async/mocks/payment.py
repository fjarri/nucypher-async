from contextlib import asynccontextmanager
from typing import NamedTuple

from pons import MethodCall, Signer

from ..drivers.payment import PaymentClient, PaymentAddress, AmountMATIC


class Policy(NamedTuple):
    # TODO: match with the names in the contract
    policy_id: bytes
    start: int
    end: int
    shares: int


class MockBackend:

    def __init__(self):
        self._balances = {}
        self._policies = {}
        self._policy_rate = AmountMATIC.gwei(1)

    @asynccontextmanager
    async def session(self):
        yield self

    # Administrative methods to modify the mocked state

    def set_balance(self, address: PaymentAddress, amount: AmountMATIC):
        self._balances[address] = amount

    def create_policy(self, policy: Policy):
        self._policies[policy.policy_id] = policy

    # Mocked contract methods (arguments are whatever MethodCall packs)

    def _call_is_policy_active(self, policy_id: bytes) -> bool:
        if policy_id not in self._policies:
            return False

        # TODO: figure out how to mock time consistently

        return True

    def _call_get_policy_cost(self, shares: int, start: int, end: int) -> int:
        return (self._policy_rate * shares * (end - start)).as_wei()

    def _transact_create_policy(
            self, signer: Signer, amount: AmountMATIC, hrac: bytes,
            address: bytes, shares: int, start: int, end: int):
        # TODO: check that the amount is correct

        # TODO: check that it is also enforced in the contract
        assert signer.address == PaymentAddress(address)

        self.create_policy(Policy(policy_id=hrac, shares=shares, start=start, end=end))

    # Mocked ``pons.ClientSession`` methods

    async def call(self, contract_address: PaymentAddress, contract_call: MethodCall):
        # TODO: check that the address is correct (that is, the correct registry was used)
        dispatch = dict(
            isPolicyActive=self._call_is_policy_active,
            getPolicyCost=self._call_get_policy_cost,
            )
        return dispatch[contract_call.method_name](*contract_call.args)

    async def transact(
            self, signer: Signer, contract_address: PaymentAddress, contract_call: MethodCall,
            amount: AmountMATIC = AmountMATIC(0)):
        # TODO: check that the address is correct (that is, the correct registry was used)
        dispatch = dict(
            createPolicy=self._transact_create_policy,
            )
        return dispatch[contract_call.method_name](signer, amount, *contract_call.args)


class MockPaymentClient(PaymentClient):

    def __init__(self):
        mock_backend = MockBackend()
        super().__init__(mock_backend)
        self._mock_backend = mock_backend

    def mock_set_balance(self, address: PaymentAddress, amount: AmountMATIC):
        self._mock_backend.set_balance(address, amount)
