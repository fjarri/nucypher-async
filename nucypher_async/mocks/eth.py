from contextlib import asynccontextmanager
from collections import defaultdict

from pons import Amount, Address, Signer, ReadMethod, WriteMethod
from pons._contract import BoundReadCall, BoundWriteCall


class MockContract:

    def __init__(self, abi):
        self._abi = abi

    def _method_by_selector(self, selector):
        for method in self._abi.read:
            if method.selector == selector:
                return method
        for method in self._abi.write:
            if method.selector == selector:
                return method
        raise ValueError(f"Could not find a method with selector {selector}")

    def _dispatch(self, data_bytes):
        selector = data_bytes[:4]
        input_bytes = data_bytes[4:]
        method = self._method_by_selector(selector)
        return method, input_bytes

    def call(self, data_bytes: bytes):
        method, input_bytes = self._dispatch(data_bytes)
        assert isinstance(method, ReadMethod)
        args = method.inputs.decode_into_tuple(input_bytes)
        result = getattr(self, method.name)(*args)
        # Note: assuming here that the result is a single value. Should be enough for mocks.
        output_bytes = method.outputs.encode(result)
        return output_bytes

    def transact(self, address, amount, data_bytes):
        method, input_bytes = self._dispatch(data_bytes)
        assert isinstance(method, WriteMethod)
        args = method.inputs.decode_into_tuple(input_bytes)
        getattr(self, method.name)(address, amount, *args)


class MockBackend():

    def __init__(self, native_currency_cls):
        self._native_currency_cls = native_currency_cls
        self._balances = defaultdict(lambda: native_currency_cls(0))
        self._contracts = {}

    def mock_register_contract(self, address: Address, mock_contract: MockContract):
        self._contracts[address] = mock_contract

    @asynccontextmanager
    async def session(self):
        yield self

    async def eth_call(self, call: BoundReadCall):
        return call.decode_output(self._contracts[call.contract_address].call(call.data_bytes))

    async def transact(self, signer: Signer, call: BoundWriteCall, amount=None):
        # TODO: change the caller's balance appropriately
        # TODO: check that the call is payable if amount is not 0
        if amount is None:
            amount = Amount(0)
        else:
            # Lower the type from specific currency
            amount = Amount.wei(amount.as_wei())

        # Lower the signer address type
        address = Address(bytes(signer.address))

        self._contracts[call.contract_address].transact(address, amount, call.data_bytes)

    def set_balance(self, address: Address, amount: Amount):
        assert isinstance(amount, self._native_currency_cls)
        self._balances[address] = amount

    async def eth_get_balance(self, address: Address) -> Amount:
        return self._balances[address]
