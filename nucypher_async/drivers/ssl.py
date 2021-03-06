from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional, Tuple
import ssl

import arrow
from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
import trio


class SSLPrivateKey:

    @classmethod
    def from_seed(cls, seed: bytes):
        private_bn = int.from_bytes(seed, 'big')
        private_key = ec.derive_private_key(private_value=private_bn, curve=ec.SECP384R1())
        return cls(private_key)

    def __init__(self, private_key: _EllipticCurvePrivateKey):
        self._private_key = private_key

    def public_key(self):
        return SSLPublicKey(self._private_key.public_key())

    @classmethod
    def from_pem_bytes(cls, data: bytes, password: Optional[bytes] = None) -> "SSLPrivateKey":
        return cls(load_pem_private_key(data, password=password))

    def to_pem_bytes(self, password: bytes) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password))


class SSLPublicKey:

    def __init__(self, public_key):
        self._public_key = public_key

    def __bytes__(self):
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint)

    def __str__(self):
        return '0x' + bytes(self).hex()

    def __eq__(self, other):
        return bytes(self) == bytes(other)


class SSLCertificate:

    class InvalidSignature(Exception):
        pass

    @classmethod
    def self_signed(cls, clock, private_key: SSLPrivateKey, host: str, days_valid: int = 365):

        public_key = private_key.public_key()

        start_date = clock.utcnow()
        end_date = start_date.shift(days=days_valid)
        fields = [x509.NameAttribute(NameOID.COMMON_NAME, host)]

        subject = issuer = x509.Name(fields)
        cert = x509.CertificateBuilder().subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(public_key._public_key)
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(start_date.datetime)
        cert = cert.not_valid_after(end_date.datetime)
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address(host))]), critical=False)
        cert = cert.sign(private_key._private_key, hashes.SHA512(), default_backend())

        return cls(cert)

    def __init__(self, certificate: x509.Certificate):
        self._certificate = certificate

    def __eq__(self, other):
        return self._certificate == other._certificate

    def to_pem_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def to_der_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.DER)

    @classmethod
    def from_pem_bytes(cls, data) -> 'SSLCertificate':
        return cls(x509.load_pem_x509_certificate(data, backend=default_backend()))

    @classmethod
    def from_der_bytes(cls, data) -> 'SSLCertificate':
        return cls(x509.load_der_x509_certificate(data, backend=default_backend()))

    def public_key(self):
        return SSLPublicKey(self._certificate.public_key())

    def verify(self):
        # Note: this is not called automatically by `httpx`, we have to call it manually
        # if we want to make sure the certificate is self-consistent.
        try:
            # TODO: this will fail if the public key is not `EllipticCurvePublicKey`.
            # This can happen when a remote node is using a custom certificate.
            # (see the docs for `cryptography.x509.Certificate.public_key`
            # for the list of possible types -
            # Different keys have different signatures of `verify()`)
            self._certificate.public_key().verify(
                self._certificate.signature,
                self._certificate.tbs_certificate_bytes,
                ec.ECDSA(self._certificate.signature_hash_algorithm))
        except exceptions.InvalidSignature as e:
            raise self.InvalidSignature(str(e)) from e

    @property
    def declared_host(self) -> str:
        return self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    @property
    def not_valid_before(self):
        return arrow.get(self._certificate.not_valid_before)

    @property
    def not_valid_after(self):
        return arrow.get(self._certificate.not_valid_after)


async def fetch_certificate(host: str, port: int) -> SSLCertificate:

    # Do not verify the certificate, it is self-signed
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    stream = await trio.open_ssl_over_tcp_stream(host, port, ssl_context=context)
    await stream.do_handshake()
    certificate_der = stream.getpeercert(True)
    return SSLCertificate.from_der_bytes(certificate_der)
