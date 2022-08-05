from abc import ABC, abstractmethod

from ..utils.logging import Logger


class BasePorter(ABC):
    """
    A base class for a stateful Porter -
    a service exposing node sampling/lookup via REST.
    """

    @abstractmethod
    async def start(self, nursery):
        ...

    @abstractmethod
    async def stop(self, nursery):
        ...

    @abstractmethod
    async def endpoint_get_ursulas(self, request_json: dict) -> dict:
        ...

    @abstractmethod
    async def endpoint_retrieve_cfrags(self, request_json: dict) -> dict:
        ...

    @abstractmethod
    async def endpoint_status(self) -> str:
        ...

    @abstractmethod
    def logger(self) -> Logger:
        ...
