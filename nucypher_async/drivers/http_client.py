import http
import ssl
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import cast

import httpx

from ..base.types import JSON
from ..utils import temp_file
from ..utils.ssl import SSLCertificate, fetch_certificate


class HTTPClientError(Exception):
    pass


class HTTPClient:
    async def fetch_certificate(self, host: str, port: int) -> SSLCertificate:
        return await fetch_certificate(host, port)

    @asynccontextmanager
    async def session(
        self, certificate: SSLCertificate | None = None
    ) -> AsyncIterator["HTTPClientSession"]:
        # It would be nice avoid saving the certificate to disk at each request.
        # Having a cache directory requires too much architectural overhead,
        # and with the current frequency of REST calls it just isn't worth it.
        # Maybe the long-standing https://bugs.python.org/issue16487 will finally get fixed,
        # and we will be able to load certificates from memory.
        verify: bool | ssl.SSLContext
        if certificate is not None:
            with temp_file(certificate.to_pem_bytes()) as certificate_filename:
                # TODO: keep an in-memory cache of contexts?
                verify = ssl.create_default_context(cafile=str(certificate_filename))
        else:
            verify = True

        # Timeouts are caught at top level, as per `trio` style.
        async with httpx.AsyncClient(verify=verify, timeout=None) as client:  # noqa: S113
            try:
                yield HTTPClientSession(client)
            except (OSError, httpx.HTTPError) as exc:
                raise HTTPClientError(str(exc)) from exc


class HTTPResponse:
    def __init__(self, response: httpx.Response):
        self._response = response

    @property
    def body_bytes(self) -> bytes:
        return self._response.read()

    @property
    def json(self) -> JSON:
        return cast("JSON", self._response.json())

    @property
    def status_code(self) -> http.HTTPStatus:
        # TODO: should we add a handling of an unrecognized status code?
        return http.HTTPStatus(self._response.status_code)


class HTTPClientSession:
    def __init__(self, client: httpx.AsyncClient):
        self._client = client

    async def get(self, url: str, params: Mapping[str, str] = {}) -> HTTPResponse:
        response = await self._client.get(url, params=params)
        return HTTPResponse(response)

    async def post(self, url: str, data: bytes) -> HTTPResponse:
        response = await self._client.post(url, content=data)
        return HTTPResponse(response)
