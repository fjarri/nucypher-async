import base64
from collections.abc import Mapping
from dataclasses import dataclass
from types import NoneType, UnionType
from typing import Any, TypeVar, Union, cast

from compages import (
    AsDataclassToDict,
    AsDict,
    AsInt,
    AsList,
    AsNone,
    AsStr,
    AsUnion,
    DataclassBase,
    IntoDataclassFromMapping,
    IntoDict,
    IntoList,
    IntoNone,
    IntoStr,
    IntoUnion,
    StructureHandler,
    Structurer,
    StructurerContext,
    StructuringError,
    UnstructureHandler,
    Unstructurer,
    UnstructurerContext,
)
from ethereum_rpc import Address
from nucypher_core import Context, RetrievalKit, TreasureMap
from nucypher_core.umbral import CapsuleFrag, PublicKey, VerifiedCapsuleFrag

from ..blockchain.identity import IdentityAddress

JSON = str | int | float | bool | None | list["JSON"] | dict[str, "JSON"]


class _IntoInt(StructureHandler):
    def structure(self, _context: StructurerContext, val: Any) -> int:
        # Need to support both strings (coming from request parameters)
        # and actual integers (coming from the JSON body)
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            try:
                return int(val)
            except ValueError as exc:
                raise StructuringError(f"Cannot parse `{val}` as integer") from exc

        raise StructuringError(f"Cannot parse a value of type `{type(val)}` as integer")


class _IntoPublicKey(StructureHandler):
    def structure(self, _context: StructurerContext, val: Any) -> PublicKey:
        if not isinstance(val, str):
            raise StructuringError("Expected a string")
        return PublicKey.from_compressed_bytes(bytes.fromhex(val))


class _AsPublicKey(UnstructureHandler):
    def unstructure(self, _context: UnstructurerContext, val: PublicKey) -> str:
        return val.to_compressed_bytes().hex()


class _IntoObjFromBase64(StructureHandler):
    def structure(self, context: StructurerContext, val: Any) -> Any:
        if not isinstance(val, str):
            raise StructuringError("Expected a string")
        data = base64.b64decode(val.encode())
        # TODO: use a Protocol to make the expectations explicit?
        return context.structure_into.from_bytes(data)  # type: ignore[union-attr]


class _AsBase64(UnstructureHandler):
    def unstructure(self, _context: UnstructurerContext, val: Any) -> str:
        return base64.b64encode(bytes(val)).decode()


class _IntoContext(StructureHandler):
    def structure(self, _context: StructurerContext, val: str) -> Context:
        if not isinstance(val, str):
            raise StructuringError("Expected a string")
        return Context(val)


class _AsContext(UnstructureHandler):
    def unstructure(self, _context: UnstructurerContext, val: Context) -> str:
        return str(val)


class _IntoAddress(StructureHandler):
    def structure(self, context: StructurerContext, val: str) -> Address:
        structure_into = cast("type[Address]", context.structure_into)
        return structure_into.from_hex(val)


class _AsAddress(UnstructureHandler):
    def unstructure(self, _context: UnstructurerContext, val: Address) -> str:
        return val.checksum


STRUCTURER = Structurer(
    {
        Address: _IntoAddress(),
        PublicKey: _IntoPublicKey(),
        TreasureMap: _IntoObjFromBase64(),
        RetrievalKit: _IntoObjFromBase64(),
        CapsuleFrag: _IntoObjFromBase64(),
        Context: _IntoContext(),
        int: _IntoInt(),
        str: IntoStr(),
        NoneType: IntoNone(),
        list: IntoList(),
        dict: IntoDict(),
        UnionType: IntoUnion(),
        Union: IntoUnion(),
        DataclassBase: IntoDataclassFromMapping(),
    },
)

UNSTRUCTURER = Unstructurer(
    {
        Address: _AsAddress(),
        PublicKey: _AsPublicKey(),
        TreasureMap: _AsBase64(),
        RetrievalKit: _AsBase64(),
        VerifiedCapsuleFrag: _AsBase64(),
        Context: _AsContext(),
        int: AsInt(),
        str: AsStr(),
        NoneType: AsNone(),
        list: AsList(),
        dict: AsDict(),
        UnionType: AsUnion(),
        Union: AsUnion(),
        DataclassBase: AsDataclassToDict(),
    },
)


_T = TypeVar("_T")


def from_json(structure_into: type[_T], obj: JSON) -> _T:
    """
    Structures incoming JSON data into the given Ethereum RPC type.
    Raises :py:class:`compages.StructuringError` on failure.
    """
    return STRUCTURER.structure_into(structure_into, obj)


def to_json(obj: Any, unstructure_as: Any = None) -> JSON:
    """
    Unstructures a given Ethereum RPC entity into a JSON-serializable value.
    Raises :py:class:`compages.UntructuringError` on failure.
    """
    # The result is `JSON` by virtue of the hooks we defined
    return cast("JSON", UNSTRUCTURER.unstructure_as(unstructure_as or type(obj), obj))


@dataclass
class UrsulaResult:
    checksum_address: IdentityAddress
    uri: str
    encrypting_key: PublicKey


@dataclass
class GetUrsulasResult:
    ursulas: list[UrsulaResult]


@dataclass
class GetUrsulasResponse:
    result: GetUrsulasResult
    version: str


@dataclass
class _GetUrsulasRequestAsQueryParams:
    quantity: int
    include_ursulas: str | None
    exclude_ursulas: str | None


@dataclass
class GetUrsulasRequest:
    quantity: int
    include_ursulas: list[IdentityAddress] | None
    exclude_ursulas: list[IdentityAddress] | None

    @classmethod
    def from_query_params(cls, params: Mapping[str, str]) -> "GetUrsulasRequest":
        """
        Since `/get_ursulas` endpoint supports the request being passed through query params,
        and it's not exactly a fully structured JSON, we need a separate method to deserialize it.
        """
        # TODO (https://github.com/fjarri-eth/compages/issues/18): have to convert it to dict
        # since `StructureDictIntoDataclass` only applies to actual dicts,
        # not to all `Mapping` implementors.
        typed_params = from_json(_GetUrsulasRequestAsQueryParams, cast("JSON", dict(params)))

        if typed_params.include_ursulas:
            include_ursulas = typed_params.include_ursulas.split(",")
        else:
            include_ursulas = None

        if typed_params.exclude_ursulas:
            exclude_ursulas = typed_params.exclude_ursulas.split(",")
        else:
            exclude_ursulas = None

        request_json = dict(
            quantity=typed_params.quantity,
            include_ursulas=include_ursulas or [],
            exclude_ursulas=exclude_ursulas or [],
        )
        return from_json(GetUrsulasRequest, cast("JSON", request_json))


@dataclass
class RetrieveCFragsRequest:
    treasure_map: TreasureMap
    retrieval_kits: list[RetrievalKit]
    alice_verifying_key: PublicKey
    bob_encrypting_key: PublicKey
    bob_verifying_key: PublicKey
    context: Context | None


# TODO (https://github.com/fjarri-eth/compages/issues/19): what would be nice to have
# is the support of "deserialization with context",
# allowing us e.g. to deserialize into VerifiedCapsuleFrag given all the verification keys.
# for now we have to do with Client* and Server* structures.


@dataclass
class ServerRetrievalResult:
    cfrags: dict[IdentityAddress, VerifiedCapsuleFrag]


@dataclass
class ServerRetrieveCFragsResult:
    retrieval_results: list[ServerRetrievalResult]


@dataclass
class ServerRetrieveCFragsResponse:
    result: ServerRetrieveCFragsResult
    version: str


@dataclass
class ClientRetrievalResult:
    cfrags: dict[IdentityAddress, CapsuleFrag]


@dataclass
class ClientRetrieveCFragsResult:
    retrieval_results: list[ClientRetrievalResult]


@dataclass
class ClientRetrieveCFragsResponse:
    result: ClientRetrieveCFragsResult
    version: str
