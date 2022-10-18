import sys
from contextlib import asynccontextmanager
from functools import wraps
from typing import (
    Callable,
    TypeVar,
    Union,
    Tuple,
    Type,
    AsyncIterator,
    Any,
    Awaitable,
    AsyncContextManager,
)
from types import TracebackType

from typing_extensions import ParamSpec, Concatenate
import trio


Param = ParamSpec("Param")
RetType = TypeVar("RetType")


def producer(
    wrapped: Callable[Concatenate[Callable[[RetType], Awaitable[None]], Param], Awaitable[None]]
) -> Callable[Param, AsyncContextManager[trio.abc.ReceiveChannel[RetType]]]:
    """
    Trio does not allow yielding from inside open nurseries,
    so this function is used to emulate the functionality of an async generator
    by using a channel.

    Note: this decorator only supports standalone functions, whose first argument is
    a callable that is used in place of `yield`.
    """

    @asynccontextmanager
    @wraps(wrapped)
    async def wrapper(*args: Any, **kwds: Any) -> AsyncIterator[trio.abc.ReceiveChannel[RetType]]:
        send_channel, receive_channel = trio.open_memory_channel[RetType](0)
        exc_info: Union[
            Tuple[Type[BaseException], BaseException, TracebackType], Tuple[None, None, None]
        ] = (None, None, None)

        async def worker() -> None:
            nonlocal exc_info
            with send_channel:
                try:
                    await wrapped(send_channel.send, *args, **kwds)
                except Exception:
                    # If we just let it raise here, this exception may be ignored.
                    # Instead, we're saving the traceback to raise it after the nursery is closed.
                    exc_info = sys.exc_info()

        async with trio.open_nursery() as nursery:
            with receive_channel:
                nursery.start_soon(worker)
                yield receive_channel
                nursery.cancel_scope.cancel()

        # If there was an exception in the wrapped function, re-raise it here.
        exc_type, exc_value, exc_traceback = exc_info
        if exc_value is not None:
            if exc_value.__traceback__ is not exc_traceback:
                raise exc_value.with_traceback(exc_traceback)
            raise exc_value
        if exc_type is not None:
            raise exc_type()

    return wrapper
