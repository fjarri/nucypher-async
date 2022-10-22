import attrs
import httpx
import json
from typing import List, Optional, Dict, Iterable, Tuple

from nucypher_core import TreasureMap, RetrievalKit, Context
from nucypher_core.umbral import PublicKey, CapsuleFrag, VerifiedCapsuleFrag

from ..drivers.identity import IdentityAddress
from ..characters.pre import DelegatorCard, RecipientCard
from .. import schema


@attrs.frozen
class UrsulaResult:
    checksum_address: IdentityAddress
    uri: str
    encrypting_key: PublicKey


@attrs.frozen
class GetUrsulasResult:
    ursulas: List[UrsulaResult]


@attrs.frozen
class GetUrsulasResponse:
    result: GetUrsulasResult
    version: str


@attrs.frozen
class GetUrsulasRequest:
    quantity: int
    include_ursulas: List[IdentityAddress] = []
    exclude_ursulas: List[IdentityAddress] = []


@attrs.frozen
class RetrieveCFragsRequest:
    treasure_map: TreasureMap
    retrieval_kits: List[RetrievalKit]
    alice_verifying_key: PublicKey
    bob_encrypting_key: PublicKey
    bob_verifying_key: PublicKey
    context: Optional[Context]


@attrs.frozen
class ClientRetrievalResult:
    cfrags: Dict[IdentityAddress, CapsuleFrag]


@attrs.frozen
class ClientRetrieveCFragsResult:
    retrieval_results: List[ClientRetrievalResult]


@attrs.frozen
class ClientRetrieveCFragsResponse:
    result: ClientRetrieveCFragsResult
    version: str


class PorterClient:
    def __init__(self, http_client: httpx.AsyncClient, host: str, port: int):
        self._http_client = http_client
        self._host = host
        self._port = port

    async def get_ursulas(
        self,
        quantity: int,
        include_ursulas: Optional[Iterable[IdentityAddress]] = None,
        exclude_ursulas: Optional[Iterable[IdentityAddress]] = None,
    ) -> Dict[IdentityAddress, Tuple[str, PublicKey]]:

        include_ursulas = list(include_ursulas) if include_ursulas else []
        exclude_ursulas = list(exclude_ursulas) if exclude_ursulas else []

        request = dict(
            quantity=str(quantity),
            include_ursulas=",".join(address.checksum for address in include_ursulas),
            exclude_ursulas=",".join(address.checksum for address in exclude_ursulas),
        )

        response = await self._http_client.get(
            f"https://{self._host}:{self._port}/get_ursulas", params=request
        )

        if response.status_code != 200:
            # TODO: a more specialized exception
            raise Exception(f"/get_ursulas failed with status {response.status_code}")

        response_json = response.json()
        parsed_response = schema.from_json(GetUrsulasResponse, response_json)

        return {
            ursula.checksum_address: (ursula.uri, ursula.encrypting_key)
            for ursula in parsed_response.result.ursulas
        }

    async def retrieve_cfrags(
        self,
        treasure_map: TreasureMap,
        retrieval_kits: Iterable[RetrievalKit],
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        context: Optional[Context] = None,
    ) -> List[Dict[IdentityAddress, VerifiedCapsuleFrag]]:

        request = RetrieveCFragsRequest(
            treasure_map=treasure_map,
            retrieval_kits=list(retrieval_kits),
            alice_verifying_key=delegator_card.verifying_key,
            bob_encrypting_key=recipient_card.encrypting_key,
            bob_verifying_key=recipient_card.verifying_key,
            context=context,
        )

        response = await self._http_client.post(
            f"https://{self._host}:{self._port}/retrieve_cfrags",
            content=json.dumps(schema.to_json(request)),
        )
        if response.status_code != 200:
            # TODO: a more specialized exception
            raise Exception(f"/retrieve_cfrags failed with status {response.status_code}")

        response_json = response.json()
        parsed_response = schema.from_json(ClientRetrieveCFragsResponse, response_json)

        processed_response = []
        for rkit, result in zip(retrieval_kits, parsed_response.result.retrieval_results):
            processed_result = {
                address: cfrag.verify(
                    rkit.capsule,
                    verifying_pk=delegator_card.verifying_key,
                    delegating_pk=treasure_map.policy_encrypting_key,
                    receiving_pk=recipient_card.encrypting_key,
                )
                for address, cfrag in result.cfrags.items()
            }
            processed_response.append(processed_result)

        return processed_response
