from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast

from ethereum_rpc import Address, Amount
from pons import BoundMethodCall, ClientSession, ContractABI, Method, Signer


class MockContract:
    def __init__(self, abi: ContractABI):
        self._abi = abi

    def _method_by_selector(self, selector: bytes) -> Method:
        for method in self._abi.method:
            if isinstance(method, Method) and method.selector == selector:
                return method
        raise ValueError(f"Could not find a method with selector {selector!r}")

    def _dispatch(self, data_bytes: bytes) -> tuple[Method, bytes]:
        selector = data_bytes[:4]
        input_bytes = data_bytes[4:]
        method = self._method_by_selector(selector)
        return method, input_bytes

    def call(self, data_bytes: bytes) -> bytes:
        method, input_bytes = self._dispatch(data_bytes)
        assert not method.mutating
        args = method.inputs.decode(input_bytes).as_tuple
        result = getattr(self, method.name)(*args)
        # Note: assuming here that if the result is a tuple,
        # it's supposed to be encoded as several values.
        # Should be fine for tests.
        results = result if isinstance(result, tuple) else (result,)
        return method.outputs.encode(results)

    def transact(self, address: Address, amount: Amount, data_bytes: bytes) -> None:
        method, input_bytes = self._dispatch(data_bytes)
        args = method.inputs.decode(input_bytes).as_tuple
        getattr(self, method.name)(address, amount, *args)


class MockBackend:
    def __init__(self) -> None:
        self._balances: dict[Address, Amount] = defaultdict(lambda: Amount.wei(0))
        self._contracts: dict[Address, MockContract] = {}

    def mock_register_contract(self, address: Address, mock_contract: MockContract) -> None:
        self._contracts[address] = mock_contract

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        # We only implement a few methods from ClientSession, but that's all we need
        yield cast("ClientSession", self)

    async def call(self, call: BoundMethodCall) -> Any:
        return call.decode_output(self._contracts[call.contract_address].call(call.data_bytes))

    async def transact(
        self, signer: Signer, call: BoundMethodCall, amount: Amount | None = None
    ) -> None:
        # TODO: change the caller's balance appropriately
        # TODO: check that the call is payable if amount is not 0

        # Lower the type from specific currency
        amount = Amount.wei(0 if amount is None else amount.as_wei())

        # Lower the signer address type
        address = Address(bytes(signer.address))

        self._contracts[call.contract_address].transact(address, amount, call.data_bytes)

    def set_balance(self, address: Address, amount: Amount) -> None:
        # Lower the type from specific currency
        self._balances[address] = Amount.wei(amount.as_wei())

    async def eth_get_balance(self, address: Address) -> Amount:
        return self._balances[address]
