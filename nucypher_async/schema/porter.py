from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from attrs import frozen
from nucypher_core import Context, RetrievalKit, TreasureMap
from nucypher_core.umbral import CapsuleFrag, PublicKey, VerifiedCapsuleFrag

from ..drivers.identity import IdentityAddress
from .base import from_json

if TYPE_CHECKING:  # pragma: no cover
    from ..base.types import JSON


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
