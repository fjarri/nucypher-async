import trio

from nucypher_async.ursula import Ursula, UrsulaServer
from nucypher_async.server import start_in_nursery


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
    for i in range(10):
        ursula = Ursula()

        if i > 0:
            seed_addresses = [f'localhost:{9150+i-1}']
        else:
            seed_addresses = []

        server = UrsulaServer(ursula, port=9150 + i, seed_addresses=seed_addresses)

        servers.append(server)

    trio.run(serve_ursulas, servers)
