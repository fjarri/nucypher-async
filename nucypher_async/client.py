import httpx
import trio

from nucypher_core import NodeMetadata, MetadataResponse, MetadataRequest, ReencryptionResponse

from .drivers.rest_client import Contact, SSLContact, HTTPError


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

        # If host is not an IP address, resolve it to an IP.
        # Nucypher nodes have their IPs included in the certificates,
        # so we will need it to make a self-consistent `SSLContact`.
        # TODO: only do that if it's not already an IP
        addrinfo = await trio.socket.getaddrinfo(contact.host, contact.port)

        # TODO: or should we select a specific entry?
        family, type_, proto, canonname, sockaddr = addrinfo[0]
        ip_addr, port = sockaddr

        # Sanity check. When would it not be the case?
        assert port == contact.port

        return SSLContact(Contact(ip_addr, port), certificate)

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
