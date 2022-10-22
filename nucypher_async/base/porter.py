from abc import ABC, abstractmethod
from typing import Dict, Optional

import trio

from ..utils.logging import Logger
from .types import JSON


class PorterRoutes:
    GET_URSULAS = "get_ursulas"
    RETRIEVE_CFRAGS = "retrieve_cfrags"
    STATUS = "status"


class BasePorterServer(ABC):
    """
    A base class for a stateful Porter -
    a service exposing node sampling/lookup via REST.
    """

    @abstractmethod
    async def start(self, nursery: trio.Nursery) -> None:
        ...

    @abstractmethod
    async def stop(self, nursery: trio.Nursery) -> None:
        ...

    @abstractmethod
    async def endpoint_get_ursulas(
        self, request_params: Dict[str, str], request_body: Optional[JSON]
    ) -> JSON:
        ...

    @abstractmethod
    async def endpoint_retrieve_cfrags(self, request_body: JSON) -> JSON:
        ...

    @abstractmethod
    async def endpoint_status(self) -> str:
        ...

    @abstractmethod
    def logger(self) -> Logger:
        ...
