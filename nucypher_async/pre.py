import trio


class Policy:

    def __init__(self, threshold, ursula_ids):
        self.threshold = threshold
        self.ursula_ids = ursula_ids


class Alice:

    async def grant(self, learner, ursula_ids, threshold, shares):

        timeout = 10

        async def check_node(ssl_contact):
            await learner._client.ping(ssl_contact)

        try:
            with trio.fail_after(timeout):
                nodes = await learner.knows_nodes(ursula_ids)
                async with trio.open_nursery() as nursery:
                    for node in nodes.values():
                        nursery.start_soon(check_node, node.ssl_contact)

            return Policy(threshold, ursula_ids)

        except trio.TooSlowError:
            raise RuntimeError("Granting timed out")


class Bob:

    async def retrieve(self, learner, policy):

        timeout = 10

        responses = set()
        finished = trio.Event()

        async def reencrypt(ursula_id):
            result = await learner.knows_nodes([ursula_id])
            await learner._client.ping(result[ursula_id].ssl_contact)
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
            raise RuntimeError("Retrieval timed out")

        return responses
