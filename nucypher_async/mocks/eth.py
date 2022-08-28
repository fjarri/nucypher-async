from contextlib import asynccontextmanager
from collections import defaultdict
from typing import Tuple, Union, TypeVar, Type, Dict, Optional, AsyncIterator, Any, cast

from pons import Amount, Address, Signer, ReadMethod, WriteMethod, ContractABI
from pons._client import ClientSession
from pons._contract import (
    BoundReadCall,
    BoundWriteCall,
)  # TODO: expose as the public API in pons


class MockContract:
    def __init__(self, abi: ContractABI):
        self._abi = abi

    def _method_by_selector(self, selector: bytes) -> Union[ReadMethod, WriteMethod]:
        for read_method in self._abi.read:
            if read_method.selector == selector:
                return read_method
        for write_method in self._abi.write:
            if write_method.selector == selector:
                return write_method
        raise ValueError(f"Could not find a method with selector {selector!r}")

    def _dispatch(self, data_bytes: bytes) -> Tuple[Union[ReadMethod, WriteMethod], bytes]:
        selector = data_bytes[:4]
        input_bytes = data_bytes[4:]
        method = self._method_by_selector(selector)
        return method, input_bytes

    def call(self, data_bytes: bytes) -> bytes:
        method, input_bytes = self._dispatch(data_bytes)
        assert isinstance(method, ReadMethod)
        args = method.inputs.decode_into_tuple(input_bytes)
        result = getattr(self, method.name)(*args)
        # Note: assuming here that the result is a single value. Should be enough for mocks.
        output_bytes = method.outputs.encode(result)
        return output_bytes

    def transact(self, address: Address, amount: Amount, data_bytes: bytes) -> None:
        method, input_bytes = self._dispatch(data_bytes)
        assert isinstance(method, WriteMethod)
        args = method.inputs.decode_into_tuple(input_bytes)
        getattr(self, method.name)(address, amount, *args)


CustomAmount = TypeVar("CustomAmount", bound=Amount)


class MockBackend:
    def __init__(self, native_currency_cls: Type[CustomAmount]):
        self._native_currency_cls = native_currency_cls
        self._balances: Dict[Address, CustomAmount] = defaultdict(lambda: native_currency_cls(0))
        self._contracts: Dict[Address, MockContract] = {}

    def mock_register_contract(self, address: Address, mock_contract: MockContract) -> None:
        self._contracts[address] = mock_contract

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        # We only implement a few methods from ClientSession, but that's all we need
        yield cast(ClientSession, self)

    async def eth_call(self, call: BoundReadCall) -> Any:
        return call.decode_output(self._contracts[call.contract_address].call(call.data_bytes))

    async def transact(
        self, signer: Signer, call: BoundWriteCall, amount: Optional[CustomAmount] = None
    ) -> None:
        # TODO: change the caller's balance appropriately
        # TODO: check that the call is payable if amount is not 0
        if amount is None:
            amount = self._native_currency_cls(0)
        else:
            # Lower the type from specific currency
            amount = self._native_currency_cls.wei(amount.as_wei())

        # Lower the signer address type
        address = Address(bytes(signer.address))

        self._contracts[call.contract_address].transact(address, amount, call.data_bytes)

    def set_balance(self, address: Address, amount: Amount) -> None:
        assert isinstance(amount, self._native_currency_cls)
        self._balances[address] = amount

    async def eth_get_balance(self, address: Address) -> CustomAmount:
        return self._balances[address]
