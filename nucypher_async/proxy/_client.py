import json
from collections.abc import Iterable
from http import HTTPStatus

from nucypher_core import Context, TreasureMap
from nucypher_core.umbral import PublicKey, VerifiedCapsuleFrag

from .._drivers.http_client import HTTPClient
from ..blockchain.identity import IdentityAddress
from ..characters.pre import DelegatorCard, EncryptedMessageMetadata, RecipientCard
from ..client.pre import BasePREConsumerClient, PRERetrievalOutcome
from . import _schema
from ._schema import ClientRetrieveCFragsResponse, GetUrsulasResponse, RetrieveCFragsRequest


class ProxyClient:
    def __init__(self, host: str, port: int, http_client: HTTPClient | None = None):
        self._http_client = http_client or HTTPClient()
        self._host = host
        self._port = port

    async def get_nodes(
        self,
        quantity: int,
        include_nodes: Iterable[IdentityAddress] | None = None,
        exclude_nodes: Iterable[IdentityAddress] | None = None,
    ) -> dict[IdentityAddress, tuple[str, PublicKey]]:
        include_nodes = list(include_nodes) if include_nodes else []
        exclude_nodes = list(exclude_nodes) if exclude_nodes else []

        request = dict(
            quantity=str(quantity),
            include_ursulas=",".join(address.checksum for address in include_nodes),
            exclude_ursulas=",".join(address.checksum for address in exclude_nodes),
        )

        async with self._http_client.session() as session:
            response = await session.get(
                f"https://{self._host}:{self._port}/get_ursulas", params=request
            )

        if response.status_code != HTTPStatus.OK:
            # TODO: a more specialized exception
            raise RuntimeError(f"/get_ursulas failed with status {response.status_code}")

        parsed_response = _schema.from_json(GetUrsulasResponse, response.json)

        return {
            node.checksum_address: (node.uri, node.encrypting_key)
            for node in parsed_response.result.ursulas
        }

    async def retrieve_cfrags(
        self,
        treasure_map: TreasureMap,
        metadatas: Iterable[EncryptedMessageMetadata],
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        context: Context | None = None,
    ) -> list[dict[IdentityAddress, VerifiedCapsuleFrag]]:
        request = RetrieveCFragsRequest(
            treasure_map=treasure_map,
            retrieval_kits=[metadata.retrieval_kit for metadata in metadatas],
            alice_verifying_key=delegator_card.verifying_key,
            bob_encrypting_key=recipient_card.encrypting_key,
            bob_verifying_key=recipient_card.verifying_key,
            context=context,
        )

        async with self._http_client.session() as session:
            response = await session.post(
                f"https://{self._host}:{self._port}/retrieve_cfrags",
                data=json.dumps(_schema.to_json(request)).encode(),
            )
        if response.status_code != HTTPStatus.OK:
            # TODO: a more specialized exception
            raise RuntimeError(f"/retrieve_cfrags failed with status {response.status_code}")

        parsed_response = _schema.from_json(ClientRetrieveCFragsResponse, response.json)

        processed_response = []
        for metadata, result in zip(
            metadatas, parsed_response.result.retrieval_results, strict=True
        ):
            processed_result = {
                address: cfrag.verify(
                    metadata.capsule,
                    verifying_pk=delegator_card.verifying_key,
                    delegating_pk=treasure_map.policy_encrypting_key,
                    receiving_pk=recipient_card.encrypting_key,
                )
                for address, cfrag in result.cfrags.items()
            }
            processed_response.append(processed_result)

        return processed_response


class ProxyPREClient(BasePREConsumerClient):
    def __init__(self, proxy_host: str, proxy_port: int, http_client: HTTPClient | None = None):
        self._proxy_client = ProxyClient(proxy_host, proxy_port, http_client=http_client)

    async def retrieve(
        self,
        treasure_map: TreasureMap,
        metadata: EncryptedMessageMetadata,
        delegator_card: DelegatorCard,
        recipient_card: RecipientCard,
        context: Context | None = None,
    ) -> PRERetrievalOutcome:
        # TODO: support multi-step retrieval in Proxy
        # (that is, when some parts were already retrieved,
        # we can list those addresses in RetrievalKit)
        # TODO (#50): support retrieving multiple kits
        cfrags = await self._proxy_client.retrieve_cfrags(
            treasure_map, [metadata], delegator_card, recipient_card, context
        )

        # TODO (#51): collect errors as well
        return PRERetrievalOutcome(cfrags=cfrags[0], errors={})
