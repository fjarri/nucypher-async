from typing import List, Optional, Dict, Mapping, cast

from attrs import frozen
from nucypher_core import TreasureMap, RetrievalKit, Context
from nucypher_core.umbral import PublicKey, CapsuleFrag, VerifiedCapsuleFrag

from ..base.types import JSON
from ..drivers.identity import IdentityAddress
from .base import from_json


@frozen
class UrsulaResult:
    checksum_address: IdentityAddress
    uri: str
    encrypting_key: PublicKey


@frozen
class GetUrsulasResult:
    ursulas: List[UrsulaResult]


@frozen
class GetUrsulasResponse:
    result: GetUrsulasResult
    version: str


@frozen
class _GetUrsulasRequestAsQueryParams:
    quantity: int
    include_ursulas: Optional[str]
    exclude_ursulas: Optional[str]


@frozen
class GetUrsulasRequest:
    quantity: int
    include_ursulas: Optional[List[IdentityAddress]]
    exclude_ursulas: Optional[List[IdentityAddress]]

    @classmethod
    def from_query_params(cls, params: Mapping[str, str]) -> "GetUrsulasRequest":
        """
        Since `/get_ursulas` endpoint supports the request being passed through query params,
        and it's not exactly a fully structured JSON, we need a separate method to deserialize it.
        """
        typed_params = from_json(_GetUrsulasRequestAsQueryParams, cast(JSON, params))

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
        return from_json(GetUrsulasRequest, cast(JSON, request_json))


@frozen
class RetrieveCFragsRequest:
    treasure_map: TreasureMap
    retrieval_kits: List[RetrievalKit]
    alice_verifying_key: PublicKey
    bob_encrypting_key: PublicKey
    bob_verifying_key: PublicKey
    context: Optional[Context]


# TODO: what would be nice to have is the support of "deserialization with context",
# allowing us e.g. to deserialize into VerifiedCapsuleFrag given all the verification keys.
# for now we have to do with Client* and Server* structures.


@frozen
class ServerRetrievalResult:
    cfrags: Dict[IdentityAddress, VerifiedCapsuleFrag]


@frozen
class ServerRetrieveCFragsResult:
    retrieval_results: List[ServerRetrievalResult]


@frozen
class ServerRetrieveCFragsResponse:
    result: ServerRetrieveCFragsResult
    version: str


@frozen
class ClientRetrievalResult:
    cfrags: Dict[IdentityAddress, CapsuleFrag]


@frozen
class ClientRetrieveCFragsResult:
    retrieval_results: List[ClientRetrievalResult]


@frozen
class ClientRetrieveCFragsResponse:
    result: ClientRetrieveCFragsResult
    version: str
