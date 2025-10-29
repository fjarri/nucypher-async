from typing import cast

from attrs import frozen
from ethereum_rpc import Address, Amount
from pons import Client, ContractABI

from ..domain import Domain
from ..drivers.pre import PREAddress, PREAmount, PREClient
from .eth import MockBackend, MockContract


@frozen
class Policy:
    # TODO: match with the names in the contract
    policy_id: bytes
    start: int
    end: int
    shares: int


class SubscriptionManager(MockContract):
    def __init__(self, abi: ContractABI):
        super().__init__(abi)
        self._policies: dict[bytes, Policy] = {}
        self._policy_rate = Amount.gwei(1)

    def isPolicyActive(self, policy_id: bytes) -> bool:  # noqa: N802
        # TODO: figure out how to mock time consistently
        return policy_id in self._policies

    def getPolicyCost(self, shares: int, start: int, end: int) -> int:  # noqa: N802
        return (self._policy_rate * shares * (end - start)).as_wei()

    def createPolicy(  # noqa: N802
        self,
        sender_address: Address,
        _amount: Amount,
        policy_id: bytes,
        address: Address,
        shares: int,
        start: int,
        end: int,
    ) -> None:
        # TODO: check that the amount is correct
        # TODO: check that timestamps are consistent
        # TODO: implement the distinction owner/sponsor from the contract

        # TODO: check that it is also enforced in the contract
        if sender_address != address:
            raise ValueError("Sender address must be the same as the target address")

        self._policies[policy_id] = Policy(policy_id=policy_id, shares=shares, start=start, end=end)


class MockPREClient(PREClient):
    def __init__(self) -> None:
        mock_backend = MockBackend()
        super().__init__(cast("Client", mock_backend), Domain.MAINNET)
        self._mock_backend = mock_backend
        mock_backend.mock_register_contract(
            self._manager.address, SubscriptionManager(self._manager.abi)
        )

    def mock_set_balance(self, address: PREAddress, amount: PREAmount) -> None:
        self._mock_backend.set_balance(address, Amount.wei(amount.as_wei()))
