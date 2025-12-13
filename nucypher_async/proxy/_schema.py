import base64
from collections.abc import Mapping
from dataclasses import dataclass
from types import NoneType, UnionType
from typing import Any, TypeVar, Union, cast

from compages import (
    StructureDictIntoDataclass,
    Structurer,
    StructuringError,
    UnstructureDataclassToDict,
    Unstructurer,
    simple_structure,
    simple_unstructure,
    structure_into_dict,
    structure_into_list,
    structure_into_none,
    structure_into_str,
    structure_into_union,
    unstructure_as_dict,
    unstructure_as_int,
    unstructure_as_list,
    unstructure_as_none,
    unstructure_as_str,
    unstructure_as_union,
)
from nucypher_core import Context, RetrievalKit, TreasureMap
from nucypher_core.umbral import CapsuleFrag, PublicKey, VerifiedCapsuleFrag

from ..blockchain.identity import IdentityAddress

JSON = str | int | float | bool | None | list["JSON"] | dict[str, "JSON"]


@simple_structure
def _structure_into_int(val: Any) -> int:
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


@simple_structure
def structure_into_identity_address(val: Any) -> IdentityAddress:
    return IdentityAddress.from_hex(val)


@simple_unstructure
def unstructure_as_identity_address(val: IdentityAddress) -> Any:
    return val.checksum


@simple_structure
def structure_into_public_key(val: str) -> PublicKey:
    return PublicKey.from_compressed_bytes(bytes.fromhex(val))


@simple_unstructure
def unstructure_as_public_key(val: PublicKey) -> str:
    return val.to_compressed_bytes().hex()


@simple_structure
def structure_into_treasure_map(val: str) -> TreasureMap:
    return TreasureMap.from_bytes(base64.b64decode(val.encode()))


@simple_unstructure
def unstructure_as_treasure_map(val: TreasureMap) -> str:
    return base64.b64encode(bytes(val)).decode()


@simple_structure
def structure_into_retrieval_kit(val: str) -> RetrievalKit:
    return RetrievalKit.from_bytes(base64.b64decode(val.encode()))


@simple_unstructure
def unstructure_as_retrieval_kit(val: RetrievalKit) -> str:
    return base64.b64encode(bytes(val)).decode()


@simple_structure
def structure_into_cfrag(val: str) -> CapsuleFrag:
    return CapsuleFrag.from_bytes(base64.b64decode(val.encode()))


@simple_unstructure
def unstructure_as_vcfrag(val: VerifiedCapsuleFrag) -> str:
    return base64.b64encode(bytes(val)).decode()


@simple_structure
def structure_into_context(val: str) -> Context:
    return Context(val)


@simple_unstructure
def unstructure_as_context(val: Context) -> str:
    return str(val)


STRUCTURER = Structurer(
    {
        IdentityAddress: structure_into_identity_address,
        PublicKey: structure_into_public_key,
        TreasureMap: structure_into_treasure_map,
        RetrievalKit: structure_into_retrieval_kit,
        CapsuleFrag: structure_into_cfrag,
        Context: structure_into_context,
        int: _structure_into_int,
        str: structure_into_str,
        NoneType: structure_into_none,
        list: structure_into_list,
        dict: structure_into_dict,
        UnionType: structure_into_union,
        Union: structure_into_union,
    },
    [StructureDictIntoDataclass()],
)

UNSTRUCTURER = Unstructurer(
    {
        IdentityAddress: unstructure_as_identity_address,
        PublicKey: unstructure_as_public_key,
        TreasureMap: unstructure_as_treasure_map,
        RetrievalKit: unstructure_as_retrieval_kit,
        VerifiedCapsuleFrag: unstructure_as_vcfrag,
        Context: unstructure_as_context,
        int: unstructure_as_int,
        str: unstructure_as_str,
        NoneType: unstructure_as_none,
        list: unstructure_as_list,
        dict: unstructure_as_dict,
        UnionType: unstructure_as_union,
        Union: unstructure_as_union,
    },
    [UnstructureDataclassToDict()],
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
