"""
What we need from a serializer/deserialized for JSON requests:
- deserialize from JSON into a fully typed structure with validation
  (supporting Optional/List/Dict/etc types, and supporting custom types, like IdentityAddress)
- create the typed structure directly with all type info available for mypy
- serialize a typed structure to JSON

Pydantic doesn't support serialization fully, Marshmallow requires creating a separate "schema"
type and creating a schema object is not type-checked.
Cattrs sort of works, but still requires some boilerplate (see below).

TODO: an ideal schema library would support all that, and:
- fully declarative use with less boilerplate, where every schema class
  would be derived from one base class;
- deserialization with context;
- anonymous dictionary fields with set keys, instead of creating a nested class as we do now.
"""

import base64
from collections.abc import Mapping
from typing import Any, TypeVar, cast

import cattrs
from attrs import frozen
from nucypher_core import Context, RetrievalKit, TreasureMap
from nucypher_core.umbral import CapsuleFrag, PublicKey, VerifiedCapsuleFrag

from ..drivers.identity import IdentityAddress

JSON = str | int | float | bool | None | list["JSON"] | dict[str, "JSON"]


def structure_identity_address(val: str, cls: type[IdentityAddress]) -> IdentityAddress:
    return cls.from_hex(val)


def unstructure_identity_address(val: IdentityAddress) -> str:
    return val.checksum


def structure_public_key(val: str, cls: type[PublicKey]) -> PublicKey:
    return cls.from_compressed_bytes(bytes.fromhex(val))


def unstructure_public_key(val: PublicKey) -> str:
    return val.to_compressed_bytes().hex()


def structure_treasure_map(val: str, cls: type[TreasureMap]) -> TreasureMap:
    return cls.from_bytes(base64.b64decode(val.encode()))


def unstructure_treasure_map(val: TreasureMap) -> str:
    return base64.b64encode(bytes(val)).decode()


def structure_retrieval_kit(val: str, cls: type[RetrievalKit]) -> RetrievalKit:
    return cls.from_bytes(base64.b64decode(val.encode()))


def unstructure_retrieval_kit(val: RetrievalKit) -> str:
    return base64.b64encode(bytes(val)).decode()


def structure_cfrag(val: str, cls: type[CapsuleFrag]) -> CapsuleFrag:
    return cls.from_bytes(base64.b64decode(val.encode()))


def unstructure_vcfrag(val: VerifiedCapsuleFrag) -> str:
    return base64.b64encode(bytes(val)).decode()


def structure_context(val: str, cls: type[Context]) -> Context:
    return cls(val)


def unstructure_context(val: Context) -> str:
    return str(val)


_CONVERTER = cattrs.Converter()

_CONVERTER.register_structure_hook(IdentityAddress, structure_identity_address)
_CONVERTER.register_unstructure_hook(IdentityAddress, unstructure_identity_address)

_CONVERTER.register_structure_hook(PublicKey, structure_public_key)
_CONVERTER.register_unstructure_hook(PublicKey, unstructure_public_key)

_CONVERTER.register_structure_hook(TreasureMap, structure_treasure_map)
_CONVERTER.register_unstructure_hook(TreasureMap, unstructure_treasure_map)

_CONVERTER.register_structure_hook(RetrievalKit, structure_retrieval_kit)
_CONVERTER.register_unstructure_hook(RetrievalKit, unstructure_retrieval_kit)

_CONVERTER.register_structure_hook(CapsuleFrag, structure_cfrag)
_CONVERTER.register_unstructure_hook(VerifiedCapsuleFrag, unstructure_vcfrag)

_CONVERTER.register_structure_hook(Context, structure_context)
_CONVERTER.register_unstructure_hook(Context, unstructure_context)


class ValidationError(Exception):
    pass


_FROM_JSON_T = TypeVar("_FROM_JSON_T")


def from_json(cls: type[_FROM_JSON_T], obj: JSON) -> _FROM_JSON_T:
    # TODO: make validation errors more human-readable
    try:
        return _CONVERTER.structure(obj, cls)
    except cattrs.BaseValidationError as exc:
        raise ValidationError(str(exc)) from exc


def to_json(obj: Any) -> JSON:
    # TODO: use the base class from `attrs` when the new version is released where it is public
    return cast("JSON", _CONVERTER.unstructure(obj))


@frozen
class UrsulaResult:
    checksum_address: IdentityAddress
    uri: str
    encrypting_key: PublicKey


@frozen
class GetUrsulasResult:
    ursulas: list[UrsulaResult]


@frozen
class GetUrsulasResponse:
    result: GetUrsulasResult
    version: str


@frozen
class _GetUrsulasRequestAsQueryParams:
    quantity: int
    include_ursulas: str | None
    exclude_ursulas: str | None


@frozen
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
        typed_params = from_json(_GetUrsulasRequestAsQueryParams, cast("JSON", params))

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


@frozen
class RetrieveCFragsRequest:
    treasure_map: TreasureMap
    retrieval_kits: list[RetrievalKit]
    alice_verifying_key: PublicKey
    bob_encrypting_key: PublicKey
    bob_verifying_key: PublicKey
    context: Context | None


# TODO: what would be nice to have is the support of "deserialization with context",
# allowing us e.g. to deserialize into VerifiedCapsuleFrag given all the verification keys.
# for now we have to do with Client* and Server* structures.


@frozen
class ServerRetrievalResult:
    cfrags: dict[IdentityAddress, VerifiedCapsuleFrag]


@frozen
class ServerRetrieveCFragsResult:
    retrieval_results: list[ServerRetrievalResult]


@frozen
class ServerRetrieveCFragsResponse:
    result: ServerRetrieveCFragsResult
    version: str


@frozen
class ClientRetrievalResult:
    cfrags: dict[IdentityAddress, CapsuleFrag]


@frozen
class ClientRetrieveCFragsResult:
    retrieval_results: list[ClientRetrievalResult]


@frozen
class ClientRetrieveCFragsResponse:
    result: ClientRetrieveCFragsResult
    version: str
