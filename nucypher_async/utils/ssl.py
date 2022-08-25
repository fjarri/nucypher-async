from ipaddress import ip_address
from pathlib import Path
from typing import Optional, Tuple
import ssl

import arrow
from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
import trio


class SSLPrivateKey:
    @classmethod
    def from_seed(cls, seed: bytes):
        private_bn = int.from_bytes(seed, "big")
        private_key = ec.derive_private_key(private_value=private_bn, curve=ec.SECP384R1())
        return cls(private_key)

    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._private_key = private_key

    def public_key(self) -> "SSLPublicKey":
        return SSLPublicKey(self._private_key.public_key())

    @classmethod
    def from_pem_bytes(cls, data: bytes, password: Optional[bytes] = None) -> "SSLPrivateKey":
        pk = load_pem_private_key(data, password=password)
        if not isinstance(pk, ec.EllipticCurvePrivateKey):
            raise ValueError("`SSLPrivateKey` can only be deserialized from an EC private key")
        return cls(pk)

    def to_pem_bytes(self, password: bytes) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )


class SSLPublicKey:
    def __init__(self, public_key: ec.EllipticCurvePublicKey):
        self._public_key = public_key

    def __bytes__(self):
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

    def __str__(self):
        return "0x" + bytes(self).hex()

    def __eq__(self, other):
        return bytes(self) == bytes(other)


class InvalidCertificate(Exception):
    pass


class SSLCertificate:
    @classmethod
    def self_signed(
        cls,
        start_date: arrow.Arrow,
        private_key: SSLPrivateKey,
        host: str,
        days_valid: int = 365,
    ) -> "SSLCertificate":
        # TODO: assert that the start date is in UTC?

        public_key = private_key.public_key()

        end_date = start_date.shift(days=days_valid)
        fields = [x509.NameAttribute(NameOID.COMMON_NAME, host)]

        subject = issuer = x509.Name(fields)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key._public_key)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(start_date.datetime)
        builder = builder.not_valid_after(end_date.datetime)

        alt_name: x509.GeneralName
        try:
            ip_addr = ip_address(host)
        except ValueError:
            alt_name = x509.DNSName(host)
        else:
            alt_name = x509.IPAddress(ip_addr)

        builder = builder.add_extension(x509.SubjectAlternativeName([alt_name]), critical=False)

        cert = builder.sign(private_key._private_key, hashes.SHA512())

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
    def from_pem_bytes(cls, data) -> "SSLCertificate":
        return cls(x509.load_pem_x509_certificate(data))

    @classmethod
    def from_der_bytes(cls, data) -> "SSLCertificate":
        return cls(x509.load_der_x509_certificate(data))

    def public_key(self):
        return SSLPublicKey(self._certificate.public_key())

    @property
    def declared_host(self) -> str:
        host = self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if not isinstance(host, str):
            # The `Name` object can technically contain bytes.
            # `cryptography` won't let you create such a certificate,
            # but some other tool might.
            raise InvalidCertificate(f"Subject hostname is not a string: {repr(host)}")
        return host

    @property
    def not_valid_before(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_before)

    @property
    def not_valid_after(self) -> arrow.Arrow:
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
