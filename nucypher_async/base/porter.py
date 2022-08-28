from abc import ABC, abstractmethod
from typing import Dict, Any

from ..utils.logging import Logger
from .types import JSON

import trio


class BasePorter(ABC):
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
    async def endpoint_get_ursulas(self, request_json: JSON) -> JSON:
        ...

    @abstractmethod
    async def endpoint_retrieve_cfrags(self, request_json: JSON) -> JSON:
        ...

    @abstractmethod
    async def endpoint_status(self) -> str:
        ...

    @abstractmethod
    def logger(self) -> Logger:
        ...
