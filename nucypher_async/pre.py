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


class Bob:

    async def retrieve(self, learner, policy):

        timeout = 10

        responses = set()
        finished = trio.Event()

        async def reencrypt(ursula_id):
            addresses = await learner.knows_nodes([ursula_id])
            await learner._client.ping(addresses[ursula_id])
            responses.add(ursula_id)
            if len(responses) == policy.threshold:
                finished.set()

        try:
            with trio.fail_after(timeout):
                async with trio.open_nursery() as nursery:
                    for ursula_id in policy.ursula_ids:
                        nursery.start_soon(reencrypt, ursula_id)
                    await finished.wait()

        except trio.TooSlowError:
            raise RuntimeError("Granting timed out")

        return responses
