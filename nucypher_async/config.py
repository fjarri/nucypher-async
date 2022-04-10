from typing import List
from pathlib import Path

import attrs
from appdirs import AppDirs

from .drivers.time import Clock, SystemClock
from .drivers.rest_client import Contact
from .drivers.identity import IdentityClient
from .drivers.payment import PaymentClient
from .drivers.rest_client import RESTClient
from .domain import Domain
from .storage import Storage, InMemoryStorage, FileSystemStorage
from .utils.logging import Logger, ConsoleHandler, RotatingFileHandler


@attrs.frozen
class UrsulaServerConfig:

    domain: Domain
    contact: Contact
    identity_client: IdentityClient
    payment_client: PaymentClient
    rest_client: RESTClient
    parent_logger: Logger
    storage: Storage
    seed_contacts: List[Contact]
    clock: Clock

    @classmethod
    def from_config_values(
            cls,
            *,
            domain,
            identity_endpoint,
            payment_endpoint,
            contact,
            log_to_console,
            log_to_file,
            persistent_storage,
            identity_client_factory=IdentityClient.from_endpoint,
            payment_client_factory=PaymentClient.from_endpoint,
            ):

        identity_client = identity_client_factory(identity_endpoint, domain)
        payment_client = payment_client_factory(payment_endpoint, domain)

        dirs = AppDirs(appname='nucypher-async')

        log_handlers = (
            ([ConsoleHandler()] if log_to_console else []) +
            ([RotatingFileHandler(log_file=Path(dirs.user_log_dir).resolve() / 'nucypher.log')] if log_to_file else []))
        logger = Logger(handlers=log_handlers)

        if persistent_storage:
            storage = FileSystemStorage(dirs.user_data_dir)
        else:
            storage = InMemoryStorage()

        if domain not in Domain:
            raise ValueError(f"Unknown domain: {domain}")

        # TODO: move these constants to domain.py?
        if domain == Domain.MAINNET:
            seed_contacts = [
                Contact('closest-seed.nucypher.network', 9151),
                Contact('seeds.nucypher.network', 9151),
                Contact('mainnet.nucypher.network', 9151)]
        elif domain == Domain.IBEX:
            seed_contacts = [
                Contact('ibex.nucypher.network', 9151)]

        rest_client = RESTClient()

        return cls(
            domain=domain,
            contact=contact,
            identity_client=identity_client,
            payment_client=payment_client,
            rest_client=rest_client,
            parent_logger=logger,
            storage=storage,
            seed_contacts=seed_contacts,
            clock=SystemClock()
            )
