import trio

from nucypher_async.ursula import Ursula
from nucypher_async.ursula_server import UrsulaServer
from nucypher_async.drivers.rest_server import start_in_nursery
from nucypher_async.drivers.rest_client import Contact


async def serve_ursulas(servers):
    async with trio.open_nursery() as nursery:
        handles = [start_in_nursery(nursery, server) for server in servers]

        try:
            await trio.sleep_forever()
        except KeyboardInterrupt:
            for handle in handles:
                handle.shutdown()


if __name__ == '__main__':

    servers = []
    for i in range(1):
        ursula = Ursula()

        if i > 0:
            seed_contacts = [Contact('127.0.0.1', 9150+i-1)]
        else:
            seed_contacts = []

        server = UrsulaServer(ursula, port=9150 + i, seed_contacts=seed_contacts)

        servers.append(server)

    trio.run(serve_ursulas, servers)
