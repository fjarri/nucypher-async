import ssl
from ipaddress import ip_address
from typing import cast, get_args

import arrow
import trio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID


class SSLPrivateKey:
    @classmethod
    def from_seed(cls, seed: bytes) -> "SSLPrivateKey":
        curve = ec.SECP384R1()
        private_bn = int.from_bytes(seed[: curve.key_size // 8], "big")
        private_key = ec.derive_private_key(private_value=private_bn, curve=curve)
        return cls(private_key)

    def __init__(self, private_key: CertificateIssuerPrivateKeyTypes):
        self.certificate_private_key = private_key

    def public_key(self) -> "SSLPublicKey":
        return SSLPublicKey(self.certificate_private_key.public_key())

    @classmethod
    def from_pem_bytes(cls, data: bytes, password: bytes | None = None) -> "SSLPrivateKey":
        private_key = load_pem_private_key(data, password=password)
        # Not everything that `load_pem_private_key()` can load
        # can serve as a certificate private key.
        key_types = get_args(CertificateIssuerPrivateKeyTypes)
        if not isinstance(private_key, key_types):
            raise TypeError(
                f"`SSLPrivateKey` can only be deserialized from {key_types}, "
                f"got {type(private_key)}"
            )
        # mypy can't understand it, but we just checked it above
        return cls(cast("CertificateIssuerPrivateKeyTypes", private_key))

    def to_pem_bytes(self, password: bytes) -> bytes:
        return self.certificate_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )


class SSLPublicKey:
    def __init__(self, public_key: CertificatePublicKeyTypes):
        self.certificate_public_key = public_key

    def __bytes__(self) -> bytes:
        return self.certificate_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def __eq__(self, other: object) -> bool:
        # Comparing byte representations since equality is not defined for RSAPublicKey
        return isinstance(other, SSLPublicKey) and bytes(self) == bytes(other)

    def __hash__(self) -> int:
        return hash((type(self), self.certificate_public_key))


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
        builder = builder.public_key(public_key.certificate_public_key)
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

        cert = builder.sign(private_key.certificate_private_key, hashes.SHA512())

        return cls(cert)

    def __init__(self, certificate: x509.Certificate):
        self._certificate = certificate

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SSLCertificate) and self._certificate == other._certificate

    def __hash__(self) -> int:
        return hash((type(self), self._certificate))

    def to_pem_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def to_der_bytes(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.DER)

    @classmethod
    def from_pem_bytes(cls, data: bytes) -> "SSLCertificate":
        return cls(x509.load_pem_x509_certificate(data))

    @classmethod
    def list_from_pem_bytes(cls, data: bytes) -> list["SSLCertificate"]:
        start_line = b"-----BEGIN CERTIFICATE-----"
        certs_bytes = data.split(start_line)
        return [cls.from_pem_bytes(start_line + cert_bytes) for cert_bytes in certs_bytes[1:]]

    @classmethod
    def from_der_bytes(cls, data: bytes) -> "SSLCertificate":
        return cls(x509.load_der_x509_certificate(data))

    def public_key(self) -> SSLPublicKey:
        public_key = self._certificate.public_key()
        # We need these to match the supported types in SSLPrivateKey
        key_types = get_args(CertificatePublicKeyTypes)
        if not isinstance(public_key, key_types):
            raise TypeError(
                f"Certificates can only have public keys of type {key_types}, "
                f"got {type(public_key)}"
            )
        # mypy can't understand it, but we just checked it above
        return SSLPublicKey(cast("CertificatePublicKeyTypes", public_key))

    @property
    def declared_host(self) -> str:
        host = self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if not isinstance(host, str):
            # The `Name` object can technically contain bytes.
            # `cryptography` won't let you create such a certificate,
            # but some other tool might.
            raise InvalidCertificate(f"Subject hostname is not a string: {host!r}")
        return host

    @property
    def not_valid_before(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_before_utc)

    @property
    def not_valid_after(self) -> arrow.Arrow:
        return arrow.get(self._certificate.not_valid_after_utc)


async def fetch_certificate(host: str, port: int) -> SSLCertificate:
    # Do not verify the certificate, it is self-signed
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        stream = await trio.open_ssl_over_tcp_stream(host, port, ssl_context=context)
        await stream.do_handshake()
        # Casting because we're explicitly requesting bytes
        certificate_der = cast("bytes", stream.getpeercert(binary_form=True))
    except (OSError, trio.BrokenResourceError) as exc:
        raise RuntimeError(str(exc) or repr(exc)) from exc

    try:
        return SSLCertificate.from_der_bytes(certificate_der)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
