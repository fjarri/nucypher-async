import http
import ssl
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import cast

import httpx

from ..base.types import JSON
from .ssl import SSLCertificate, fetch_certificate, make_client_ssl_context


class HTTPClientError(Exception):
    pass


class HTTPClient:
    # The default certificate cache size is chosen to cover the possible size of the network,
    # which at its best only had a few hundred nodes.
    def __init__(self, certificate_cache_size: int = 1024):
        @lru_cache(maxsize=certificate_cache_size)
        def cached_ssl_context(certificate: SSLCertificate) -> ssl.SSLContext:
            return make_client_ssl_context(certificate)

        self._cached_ssl_context = cached_ssl_context

    async def fetch_certificate(self, host: str, port: int) -> SSLCertificate:
        return await fetch_certificate(host, port)

    @asynccontextmanager
    async def session(
        self, certificate: SSLCertificate | None = None
    ) -> AsyncIterator["HTTPClientSession"]:
        verify = self._cached_ssl_context(certificate) if certificate is not None else True

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
    def status_code(self) -> http.HTTPStatus | None:
        try:
            return http.HTTPStatus(self._response.status_code)
        except ValueError:
            return None


class HTTPClientSession:
    def __init__(self, client: httpx.AsyncClient):
        self._client = client

    async def get(self, url: str, params: Mapping[str, str] = {}) -> HTTPResponse:
        response = await self._client.get(url, params=params)
        return HTTPResponse(response)

    async def post(self, url: str, data: bytes) -> HTTPResponse:
        response = await self._client.post(url, content=data)
        return HTTPResponse(response)
