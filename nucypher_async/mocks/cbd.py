from typing import cast

from ethereum_rpc import Amount
from pons import Client, ContractABI

from ..domain import Domain
from ..drivers.cbd import CBDAddress, CBDAmount, CBDClient
from .eth import MockBackend, MockContract


class Coordinator(MockContract):
    def __init__(self, abi: ContractABI):
        super().__init__(abi)


class MockCBDClient(CBDClient):
    def __init__(self) -> None:
        mock_backend = MockBackend()
        super().__init__(cast("Client", mock_backend), Domain.MAINNET)
        self._mock_backend = mock_backend
        mock_backend.mock_register_contract(
            self._coordinator.address, Coordinator(self._coordinator.abi)
        )

    def mock_set_balance(self, address: CBDAddress, amount: CBDAmount) -> None:
        self._mock_backend.set_balance(address, Amount.wei(amount.as_wei()))
