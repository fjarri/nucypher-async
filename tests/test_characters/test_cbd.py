import os

from nucypher_core.ferveo import (
    AggregatedTranscript,
    Dkg,
    DkgPublicKey,
    Keypair,
    Validator,
    ValidatorMessage,
)

from nucypher_async.characters.cbd import Decryptor, Encryptor
from nucypher_async.drivers.identity import IdentityAddress
from nucypher_async.master_key import MasterKey


def test_encrypt_and_decrypt() -> None:
    ritual_id = 42
    shares = 3
    threshold = 2

    validator_keypairs = [Keypair.random() for _ in range(shares)]
    validators = [
        Validator(IdentityAddress(os.urandom(20)).checksum, keypair.public_key(), i)
        for i, keypair in enumerate(validator_keypairs)
    ]

    # Validators must be sorted by their public key
    validators.sort(key=lambda validator: validator.address)

    validator_messages = []
    for validator in validators:
        dkg = Dkg(
            tau=ritual_id,
            shares_num=shares,
            security_threshold=threshold,
            validators=validators,
            me=validator,
        )
        transcript = dkg.generate_transcript()
        validator_messages.append(ValidatorMessage(validator, transcript))

    # any validator can generate the same aggregated transcript
    aggregator = validators[0]
    dkg = Dkg(
        tau=ritual_id,
        shares_num=shares,
        security_threshold=threshold,
        validators=validators,
        me=aggregator,
    )
    server_aggregate: AggregatedTranscript = dkg.aggregate_transcripts(validator_messages)
    dkg_public_key: DkgPublicKey = server_aggregate.public_key

    encryptor = Encryptor(MasterKey.random())
    decryptor = Decryptor(MasterKey.random())

    message = b"message"
    message_kit = encryptor.encrypt(dkg_public_key, message)
