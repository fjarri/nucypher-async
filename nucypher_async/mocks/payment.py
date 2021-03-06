from contextlib import asynccontextmanager
from typing import NamedTuple

from pons import Signer, Amount, Address

from ..domain import Domain
from ..drivers.payment import PaymentClient, PaymentAddress, AmountMATIC
from .eth import MockBackend, MockContract


class Policy(NamedTuple):
    # TODO: match with the names in the contract
    policy_id: bytes
    start: int
    end: int
    shares: int


class SubscriptionManager(MockContract):

    def __init__(self, abi):
        super().__init__(abi)
        self._balances = {}
        self._policies = {}
        self._policy_rate = Amount.gwei(1)

    def isPolicyActive(self, policy_id: bytes):
        if policy_id not in self._policies:
            return False

        # TODO: figure out how to mock time consistently

        return True

    def getPolicyCost(self, shares: int, start: int, end: int) -> int:
        return (self._policy_rate * shares * (end - start)).as_wei()

    def createPolicy(self,
            sender_address: Address,
            amount: Amount, policy_id: bytes, address: Address, shares: int, start: int, end: int):
        # TODO: check that the amount is correct
        # TODO: check that timestamps are consistent
        # TODO: implement the distinction owner/sponsor from the contract

        # TODO: check that it is also enforced in the contract
        assert sender_address == address

        self._policies[policy_id] = Policy(policy_id=policy_id, shares=shares, start=start, end=end)


class MockPaymentClient(PaymentClient):

    def __init__(self):
        mock_backend = MockBackend(AmountMATIC)
        super().__init__(mock_backend, Domain.MAINNET)
        self._mock_backend = mock_backend
        mock_backend.mock_register_contract(self._manager.address, SubscriptionManager(self._manager.abi))

    def mock_set_balance(self, address: PaymentAddress, amount: AmountMATIC):
        self._mock_backend.set_balance(address, amount)
