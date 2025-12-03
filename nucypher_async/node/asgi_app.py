import trio
from nucypher_core import EncryptedThresholdDecryptionRequest, MetadataRequest, ReencryptionRequest

from ..drivers.asgi import BinaryResponse, HTMLResponse, JSONResponse, Request, Route, make_asgi_app
from ..drivers.http_server import HTTPServableApp
from ..node_base import InvalidMessage, NodeRoutes
from .server import NodeServer


def make_node_asgi_app(server: NodeServer) -> HTTPServableApp:
    http_server = NodeServerAsHTTPServer(server)
    return make_asgi_app(
        parent_logger=server.logger(),
        routes=[
            Route(NodeRoutes.PING, ["GET"], http_server.ping),
            Route(NodeRoutes.NODE_METADATA, ["POST"], http_server.node_metadata),
            Route(NodeRoutes.PUBLIC_INFORMATION, ["GET"], http_server.public_information),
            Route(NodeRoutes.REENCRYPT, ["POST"], http_server.reencrypt),
            Route(NodeRoutes.CONDITION_CHAINS, ["GET"], http_server.condition_chains),
            Route(NodeRoutes.DECRYPT, ["POST"], http_server.decrypt),
            Route(NodeRoutes.STATUS, ["GET"], http_server.status),
        ],
        on_startup=http_server.start,
        on_shutdown=http_server.stop,
    )


class NodeServerAsHTTPServer:
    def __init__(self, server: NodeServer):
        self._server = server

    async def start(self, nursery: trio.Nursery) -> None:
        await self._server.start(nursery)

    async def stop(self, _nursery: trio.Nursery) -> None:
        await self._server.stop()

    async def ping(self, request: Request) -> BinaryResponse:
        response = await self._server.ping(request.remote_host)
        return BinaryResponse(data=response.encode())

    async def node_metadata(self, request: Request) -> BinaryResponse:
        try:
            typed_request = MetadataRequest.from_bytes(await request.body_bytes())
        except ValueError as exc:
            raise InvalidMessage.for_message(MetadataRequest, exc) from exc
        response = await self._server.node_metadata(request.remote_host, typed_request)
        return BinaryResponse(data=bytes(response))

    async def public_information(self, _request: Request) -> BinaryResponse:
        response = await self._server.public_information()
        return BinaryResponse(data=bytes(response))

    async def reencrypt(self, request: Request) -> BinaryResponse:
        try:
            typed_request = ReencryptionRequest.from_bytes(await request.body_bytes())
        except ValueError as exc:
            raise InvalidMessage.for_message(ReencryptionRequest, exc) from exc
        response = await self._server.reencrypt(typed_request)
        return BinaryResponse(data=bytes(response))

    async def condition_chains(self, _request: Request) -> JSONResponse:
        return JSONResponse(data=await self._server.condition_chains())

    async def decrypt(self, request: Request) -> BinaryResponse:
        try:
            typed_request = EncryptedThresholdDecryptionRequest.from_bytes(
                await request.body_bytes()
            )
        except ValueError as exc:
            raise InvalidMessage.for_message(EncryptedThresholdDecryptionRequest, exc) from exc
        response = await self._server.decrypt(typed_request)
        return BinaryResponse(data=bytes(response))

    async def status(self, _request: Request) -> HTMLResponse:
        return HTMLResponse(page=await self._server.status())
