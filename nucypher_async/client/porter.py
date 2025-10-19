import json
from collections.abc import Iterable
from http import HTTPStatus

import httpx
from nucypher_core import Context, RetrievalKit, TreasureMap
from nucypher_core.umbral import PublicKey, VerifiedCapsuleFrag

from .. import schema
from ..characters.pre import DelegatorCard, RecipientCard
from ..drivers.identity import IdentityAddress
from ..schema.porter import (
    ClientRetrieveCFragsResponse,
    GetUrsulasResponse,
    RetrieveCFragsRequest,
)


class PorterClient:
    def __init__(self, host: str, port: int, http_client: httpx.AsyncClient | None):
        if http_client is not None:
            self._http_client = http_client
        else:
            self._http_client = httpx.AsyncClient()
        self._host = host
        self._port = port

    async def get_ursulas(
        self,
        quantity: int,
        include_ursulas: Iterable[IdentityAddress] | None = None,
        exclude_ursulas: Iterable[IdentityAddress] | None = None,
    ) -> dict[IdentityAddress, tuple[str, PublicKey]]:
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

        if response.status_code != HTTPStatus.OK:
            # TODO: a more specialized exception
            raise RuntimeError(f"/get_ursulas failed with status {response.status_code}")

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
        context: Context | None = None,
    ) -> list[dict[IdentityAddress, VerifiedCapsuleFrag]]:
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
        if response.status_code != HTTPStatus.OK:
            # TODO: a more specialized exception
            raise RuntimeError(f"/retrieve_cfrags failed with status {response.status_code}")

        response_json = response.json()
        parsed_response = schema.from_json(ClientRetrieveCFragsResponse, response_json)

        processed_response = []
        for rkit, result in zip(
            retrieval_kits, parsed_response.result.retrieval_results, strict=True
        ):
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
