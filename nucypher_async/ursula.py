import trio

from .certificate import SSLPrivateKey, SSLCertificate
from .middleware import NetworkMiddleware, HttpError
from .protocol import NodeID, Metadata, ContactRequest
from .learner import Learner
from .utils import BackgroundTask, Contact, SSLContact


class Ursula:

    def __init__(self):
        self.id = NodeID.random()


class UrsulaServer:

    def __init__(self, ursula, middleware=None, port=9151, host='127.0.0.1', seed_contacts=[]):

        # TODO: generate the seed from some root secret material.
        self._ssl_private_key = SSLPrivateKey.from_seed(b'asdasdasd')
        self._ssl_certificate = SSLCertificate.self_signed(self._ssl_private_key, host)

        contact = Contact(host=host, port=port)
        self.ssl_contact = SSLContact(contact, self._ssl_certificate)

        if middleware is None:
            middleware = NetworkMiddleware()

        self.ursula = ursula
        self._metadata = Metadata(
            node_id=self.ursula.id,
            ssl_contact=self.ssl_contact)

        self.learner = Learner(middleware, my_metadata=self._metadata, seed_contacts=seed_contacts)

        self.started = False

    def metadata(self):
        return self._metadata

    def start(self, nursery):
        assert not self.started

        # TODO: make sure a proper cleanup happens if the start-up fails halfway
        self._learning_task = BackgroundTask(nursery, self._learn)

        self.started = True

    async def _learn(self, this_task):
        try:
            with trio.fail_after(5):
                await self.learner.learning_round()
        except trio.TooSlowError:
            # Better luck next time
            pass
        except Exception as e:
            # TODO: log the error here
            raise
            pass
        await this_task.restart_in(10)

    def stop(self):
        assert self.started

        self._learning_task.stop()

        self.started = False

    async def endpoint_ping(self):
        return self.metadata().to_json()

    async def endpoint_get_contacts(self, contact_request_json):
        contact_request = ContactRequest.from_json(contact_request_json)
        # Alternatively, we could return all known contacts,
        # but that would just propagate garbage through the network.
        if contact_request.signed_contact:
            await self.learner.add_contact(contact_request.signed_contact)
        return self.learner.verified_contact_package().to_json()
