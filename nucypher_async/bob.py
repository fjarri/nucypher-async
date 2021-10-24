import trio


class Bob:

    async def retrieve(self, learner, policy):

        timeout = 10

        responses = set()
        finished = trio.Event()

        async def reencrypt(ursula_id):
            addresses = await learner.knows_nodes([ursula_id])
            await learner._middleware.ping(addresses[ursula_id])
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
