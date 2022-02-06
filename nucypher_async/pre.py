import trio

from nucypher_core import TreasureMap, MessageKit, HRAC
from nucypher_core.umbral import SecretKeyFactory, Signer, SecretKey, generate_kfrags

class Policy:

    def __init__(self, encrypted_treasure_map, encrypting_key):
        self.encrypted_treasure_map = encrypted_treasure_map
        self.encrypting_key = encrypting_key


class Alice:

    def __init__(self):
        self._skf = SecretKeyFactory.random()
        self._signer = Signer(SecretKey.random())
        self.verifying_key = self._signer.verifying_key()

    async def grant(self, learner, bob, label, threshold, shares, handpicked_addresses=None):

        # TODO: sample Ursulas from the blockchain here

        policy_sk = self._skf.make_key(label)

        kfrags = generate_kfrags(
            delegating_sk=policy_sk,
            receiving_pk=bob.public_key,
            signer=self._signer,
            threshold=threshold,
            shares=shares,
            sign_delegating_key=True,
            sign_receiving_key=True)

        assigned_kfrags = {}
        async with learner.verified_nodes_iter(handpicked_addresses) as aiter:
            async for node in aiter:
                assigned_kfrags[node.metadata.payload.staker_address] = (node.metadata.payload.encrypting_key, kfrags.pop())
                if len(assigned_kfrags) == shares:
                    break

        hrac = HRAC(
            publisher_verifying_key=self.verifying_key,
            bob_verifying_key=bob.verifying_key,
            label=label)
        treasure_map = TreasureMap(
            signer=self._signer,
            hrac=hrac,
            policy_encrypting_key=policy_sk.public_key(),
            assigned_kfrags=assigned_kfrags,
            threshold=threshold)
        encrypted_treasure_map = treasure_map.encrypt(self._signer, bob.public_key)

        return Policy(
            encrypted_treasure_map=encrypted_treasure_map,
            encrypting_key=policy_sk.public_key())


class Bob:

    def __init__(self):
        self._decrypting_key = SecretKey.random()
        self._signer = Signer(SecretKey.random())

        self.public_key = self._decrypting_key.public_key()
        self.verifying_key = self._signer.verifying_key()

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
