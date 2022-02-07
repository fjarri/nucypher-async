import httpx

from nucypher_core import NodeMetadata, MetadataResponse, MetadataRequest, ReencryptionResponse

from .drivers.errors import HTTPError
from .drivers.rest_client import Contact, SSLContact


class NetworkClient:
    """
    The client's job is to serialize the arguments, deserialize the result,
    catch HTTPError from middleware and convert it to more specific exceptions -
    the callers shouldn't worry about HTTP status codes.
    This is the counterpart of UrsulaSever.
    """

    def __init__(self, rest_client):
        self._rest_client = rest_client

    async def fetch_certificate(self, contact: Contact) -> SSLContact:
        certificate = await self._rest_client.fetch_certificate(contact)
        return SSLContact(contact, certificate)

    async def ping(self, ssl_contact: SSLContact):
        try:
            remote_host = await self._rest_client.ping(ssl_contact)
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e
        return remote_host

    async def node_metadata_post(self, ssl_contact: SSLContact, fleet_state_checksum, announce_nodes):
        # TODO: move outside of this method, this is not the place to create it
        request = MetadataRequest(fleet_state_checksum=fleet_state_checksum,
                                  announce_nodes=announce_nodes)

        try:
            response_bytes = await self._rest_client.node_metadata_post(ssl_contact, bytes(request))
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e

        return MetadataResponse.from_bytes(response_bytes)

    async def public_information(self, ssl_contact: SSLContact):
        try:
            response_bytes = await self._rest_client.public_information(ssl_contact)
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e

        return NodeMetadata.from_bytes(response_bytes)

    async def reencrypt(self, ssl_contact: SSLContact, reencryption_request):
        try:
            response_bytes = await self._rest_client.reencrypt(ssl_contact, bytes(reencryption_request))
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e

        return ReencryptionResponse.from_bytes(response_bytes)
