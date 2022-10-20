import base64
from typing import Type, TypeVar, cast, Any

import cattrs
from nucypher_core import TreasureMap, Context, RetrievalKit
from nucypher_core.umbral import PublicKey, VerifiedCapsuleFrag

from .drivers.identity import IdentityAddress
from .base.types import JSON


def structure_identity_address(val: str, cls: Type[IdentityAddress]) -> IdentityAddress:
    return cls.from_hex(val)


def unstructure_identity_address(val: IdentityAddress) -> str:
    return val.checksum


def structure_public_key(val: str, cls: Type[PublicKey]) -> PublicKey:
    return cls.from_bytes(bytes.fromhex(val))


def unstructure_public_key(val: PublicKey) -> str:
    return bytes(val).hex()


def structure_treasure_map(val: str, cls: Type[TreasureMap]) -> TreasureMap:
    return cls.from_bytes(base64.b64decode(val.encode()))


def unstructure_treasure_map(val: TreasureMap) -> str:
    return base64.b64encode(bytes(val)).decode()


def structure_retrieval_kit(val: str, cls: Type[RetrievalKit]) -> RetrievalKit:
    return cls.from_bytes(base64.b64decode(val.encode()))


def unstructure_retrieval_kit(val: RetrievalKit) -> str:
    return base64.b64encode(bytes(val)).decode()


def unstructure_vcfrag(val: VerifiedCapsuleFrag) -> str:
    return base64.b64encode(bytes(val)).decode()


def structure_context(val: str, cls: Type[Context]) -> Context:
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

_CONVERTER.register_unstructure_hook(VerifiedCapsuleFrag, unstructure_vcfrag)

_CONVERTER.register_structure_hook(Context, structure_context)
_CONVERTER.register_unstructure_hook(Context, unstructure_context)


_FROM_JSON_T = TypeVar("_FROM_JSON_T")


def from_json(cls: Type[_FROM_JSON_T], obj: JSON) -> _FROM_JSON_T:
    # TODO: make validation errors more human-readable
    return _CONVERTER.structure(obj, cls)


def to_json(obj: Any) -> JSON:
    # TODO: use the base class from `attrs` when the new version is released where it is public
    return cast(JSON, _CONVERTER.unstructure(obj))
