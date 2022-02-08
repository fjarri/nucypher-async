import pytest

import nucypher_async.utils.logging as logging


@pytest.fixture(scope='session')
def logger():
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(
        level=logging.DEBUG,
        handlers=[logging.ConsoleHandler(stderr_at=None)])
