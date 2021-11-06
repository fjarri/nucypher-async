import trio


class Policy:

    def __init__(self, threshold, ursula_ids):
        self.threshold = threshold
        self.ursula_ids = ursula_ids


class Alice:

    async def grant(self, learner, threshold, shares):

        ursula_ids = [str(i) for i in range(shares)]
        timeout = 10

        async def check_node(address):
            await learner._client.ping(address)

        try:
            with trio.fail_after(timeout):
                addresses = await learner.knows_nodes(ursula_ids)

                async with trio.open_nursery() as nursery:
                    for id in ursula_ids:
                        nursery.start_soon(check_node, addresses[id])

            return Policy(threshold, ursula_ids)

        except trio.TooSlowError:
            raise RuntimeError("Granting timed out")
