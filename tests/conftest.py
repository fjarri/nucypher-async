import pytest

import nucypher_async.utils.logging as logging
from nucypher_async.mocks import MockIdentityClient, MockPaymentClient, MockClock
from nucypher_async.ursula import Ursula
from nucypher_async.mocks import MockNetwork


@pytest.fixture(scope="session")
def logger():
    # TODO: we may add a CLI option to reduce the verbosity of test logging
    return logging.Logger(level=logging.DEBUG, handlers=[logging.ConsoleHandler(stderr_at=None)])


@pytest.fixture
async def mock_clock():
    return MockClock()


@pytest.fixture
def ursulas():
    yield [Ursula() for i in range(10)]


@pytest.fixture
async def mock_network(nursery):
    yield MockNetwork(nursery)


@pytest.fixture
def mock_identity_client():
    yield MockIdentityClient()


@pytest.fixture
def mock_payment_client():
    yield MockPaymentClient()
