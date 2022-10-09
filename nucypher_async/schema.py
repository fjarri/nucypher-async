from typing import List, Type, TypeVar, cast, Any
from attrs import frozen
import cattrs

from nucypher_core.umbral import PublicKey

from .drivers.identity import IdentityAddress
from .base.types import JSON


def structure_identity_address(val: str, cls: Type[IdentityAddress]) -> IdentityAddress:
    return cls.from_hex(val)


def unstructure_identity_address(val: IdentityAddress) -> str:
    return val.checksum


def structure_public_key(val: str, cls: Type[PublicKey]) -> PublicKey:
    return PublicKey.from_bytes(bytes.fromhex(val))


def unstructure_public_key(val: PublicKey) -> str:
    return bytes(val).hex()


_CONVERTER = cattrs.Converter()

_CONVERTER.register_structure_hook(IdentityAddress, structure_identity_address)
_CONVERTER.register_unstructure_hook(IdentityAddress, unstructure_identity_address)

_CONVERTER.register_structure_hook(PublicKey, structure_public_key)
_CONVERTER.register_unstructure_hook(PublicKey, unstructure_public_key)


_FROM_JSON_T = TypeVar("_FROM_JSON_T")


def from_json(cls: Type[_FROM_JSON_T], obj: JSON) -> _FROM_JSON_T:
    # TODO: make validation errors more human-readable
    return _CONVERTER.structure(obj, cls)


def to_json(obj: Any) -> JSON:
    # TODO: use the base class from `attrs` when the new version is released where it is public
    return cast(JSON, _CONVERTER.unstructure(obj))
