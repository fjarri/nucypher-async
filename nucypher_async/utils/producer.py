import inspect
import sys
from contextlib import asynccontextmanager
from functools import wraps

import trio


def producer(wrapped):
    """
    Trio does not allow yielding from inside open nurseries,
    so this function is used to emulate the functionality of an async generator
    by using a channel.

    Note: this decorator only supports standalone functions and instance methods
    (not static- or classmethods), and for the instance methods the first argument must be ``self``.
    """

    # We are modifying the wrapped callable's signature, adding an argument.
    # It is quite tricky to make it work with all possible function/method declarations,
    # so we're limiting ourselves to two cases: a standalone function,
    # or a typical instance method with `self` as the first argument.
    signature = inspect.signature(wrapped)
    decorated_method = (
        len(signature.parameters) > 0
        and list(signature.parameters.keys())[0] == 'self')

    @asynccontextmanager
    @wraps(wrapped)
    async def wrapper(*args, **kwds):
        send_channel, receive_channel = trio.open_memory_channel(0)
        exc_info = None

        # Add the yield function to the arguments.
        # In the decorated method case, it will be bound to the instance
        # **after** the decorator is applied, so we need to add our new arg after ``self``.
        if decorated_method:
            self_, *other_args = args
            args_with_yield = (self_, send_channel.send, *other_args)
        else:
            args_with_yield = (send_channel.send, *args)

        async def worker():
            nonlocal exc_info
            with send_channel:
                try:
                    await wrapped(*args_with_yield, **kwds)
                except Exception as e:
                    # If we just let it raise here, this exception may be ignored.
                    # Instead, we're saving the traceback to raise it after the nursery is closed.
                    exc_info = sys.exc_info()

        async with trio.open_nursery() as nursery:
            with receive_channel:
                nursery.start_soon(worker)
                yield receive_channel
                nursery.cancel_scope.cancel()

        # If there was an exception in the wrapped function, re-raise it here.
        if exc_info:
            exc_type, exc_value, exc_traceback = exc_info
            if exc_value is None:
                exc_value = exc_type()
            if exc_value.__traceback__ is not exc_traceback:
                raise exc_value.with_traceback(exc_traceback)
            raise exc_value

    wrapper.raw = wrapped
    return wrapper
