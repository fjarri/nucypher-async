from contextlib import asynccontextmanager
import http
import httpx

from .drivers.rest_client import Contact, SSLContact
from .protocol import Metadata, ContactPackage, SignedContact, ContactRequest


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

    async def ping(self, ssl_contact: SSLContact) -> Metadata:
        try:
            metadata_json = await self._rest_client.ping(ssl_contact)
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e
        return Metadata.from_json(metadata_json)

    async def get_contacts(self, ssl_contact: SSLContact, contact_request: ContactRequest) -> ContactPackage:
        try:
            contact_package_json = await self._rest_client.get_contacts(ssl_contact, contact_request.to_json())
        except HTTPError as e:
            # TODO: diversify the errors?
            raise RuntimeError(e) from e
        return ContactPackage.from_json(contact_package_json)
