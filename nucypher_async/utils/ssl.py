from ipaddress import ip_address
from typing import Optional, Any, List, cast, get_args
import ssl

import arrow
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CERTIFICATE_PRIVATE_KEY_TYPES,
    CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
import trio


class SSLPrivateKey:
    @classmethod
    def from_seed(cls, seed: bytes) -> "SSLPrivateKey":
        private_bn = int.from_bytes(seed, "big")
        private_key = ec.derive_private_key(private_value=private_bn, curve=ec.SECP384R1())
        return cls(private_key)

    def __init__(self, private_key: CERTIFICATE_PRIVATE_KEY_TYPES):
        self._private_key = private_key

    def public_key(self) -> "SSLPublicKey":
        return SSLPublicKey(self._private_key.public_key())

    @classmethod
    def from_pem_bytes(cls, data: bytes, password: Optional[bytes] = None) -> "SSLPrivateKey":
        private_key = load_pem_private_key(data, password=password)
        # Not everything that `load_pem_private_key()` can load
        # can serve as a certificate private key.
        key_types = get_args(CERTIFICATE_PRIVATE_KEY_TYPES)
        if not isinstance(private_key, key_types):
            raise ValueError(
                f"`SSLPrivateKey` can only be deserialized from {key_types}, "
                f"got {type(private_key)}"
            )
        # mypy can't understand it, but we just checked it above
        return cls(cast(CERTIFICATE_PRIVATE_KEY_TYPES, private_key))

    def to_pem_bytes(self, password: bytes) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )


class SSLPublicKey:
    def __init__(self, public_key: CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES):
        self._public_key = public_key

    def __bytes__(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def __eq__(self, other: Any) -> bool:
        # Comparing byte representations since equality is not defined for RSAPublicKey
        return isinstance(other, SSLPublicKey) and bytes(self) == bytes(other)


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

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, SSLCertificate) and self._certificate == other._certificate

    def to_pem_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def to_der_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.DER)

    @classmethod
    def from_pem_bytes(cls, data: bytes) -> "SSLCertificate":
        return cls(x509.load_pem_x509_certificate(data))

    @classmethod
    def list_from_pem_bytes(cls, data: bytes) -> List["SSLCertificate"]:
        start_line = b"-----BEGIN CERTIFICATE-----"
        certs_bytes = data.split(start_line)
        certs = []
        for cert_bytes in certs_bytes[1:]:
            certs.append(cls.from_pem_bytes(start_line + cert_bytes))
        return certs

    @classmethod
    def from_der_bytes(cls, data: bytes) -> "SSLCertificate":
        return cls(x509.load_der_x509_certificate(data))

    def public_key(self) -> SSLPublicKey:
        public_key = self._certificate.public_key()
        # We need these to match the supported types in SSLPrivateKey
        key_types = get_args(CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES)
        if not isinstance(public_key, key_types):
            raise ValueError(
                f"Certificates can only have public keys of type {key_types}, "
                f"got {type(public_key)}"
            )
        # mypy can't understand it, but we just checked it above
        return SSLPublicKey(cast(CERTIFICATE_ISSUER_PUBLIC_KEY_TYPES, public_key))

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
    # Casting because we're explicitly requesting bytes
    certificate_der = cast(bytes, stream.getpeercert(binary_form=True))
    return SSLCertificate.from_der_bytes(certificate_der)
