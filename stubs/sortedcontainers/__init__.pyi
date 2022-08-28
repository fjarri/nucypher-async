# As we wait for the long-running PR https://github.com/grantjenks/python-sortedcontainers/pull/107
# to be merged, here are our custom type annotations.
# These are technically stricter than what the library accepts.

from typing import Callable, Any, Generic, TypeVar, Sequence

T = TypeVar("T")

class SortedKeyList(Generic[T]):
    def __init__(self, key: Callable[[T], Any]): ...
    def add(self, value: T): ...
    def __getitem__(self, index: int) -> T: ...
