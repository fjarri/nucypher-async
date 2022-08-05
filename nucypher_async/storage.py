from abc import ABC, abstractmethod

from pathlib import Path

from appdirs import AppDirs
from nucypher_core import NodeMetadata


class BaseStorage(ABC):

    @abstractmethod
    def get_my_metadata(self) -> NodeMetadata:
        ...

    @abstractmethod
    def set_my_metadata(self, metadata: NodeMetadata):
        ...


class InMemoryStorage(BaseStorage):

    def __init__(self):
        self._my_metadata = None

    def get_my_metadata(self):
        return self._my_metadata

    def set_my_metadata(self, metadata):
        self._my_metadata = metadata


class FileSystemStorage(BaseStorage):

    def __init__(self, storage_dir: Path):
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _my_metadata_path(self):
        return self._storage_dir / 'operator.metadata'

    def get_my_metadata(self):
        metadata_path = self._my_metadata_path()
        if not metadata_path.is_file():
            return None

        with open(metadata_path, 'rb') as f:
            metadata = f.read()

        return NodeMetadata.from_bytes(metadata)

    def set_my_metadata(self, metadata):
        metadata_path = self._my_metadata_path()
        with open(metadata_path, 'wb') as f:
            f.write(bytes(metadata))

