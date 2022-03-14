import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional, Tuple
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
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
        return self._private_key.public_key()

    def to_pem_bytes(self, password: bytes) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password))


class SSLCertificate:

    @classmethod
    def self_signed(cls, private_key: SSLPrivateKey, host: str, days_valid: int = 365):

        public_key = private_key.public_key()

        now = datetime.datetime.utcnow()
        fields = [x509.NameAttribute(NameOID.COMMON_NAME, host)]

        subject = issuer = x509.Name(fields)
        cert = x509.CertificateBuilder().subject_name(subject)
        cert = cert.issuer_name(issuer)
        cert = cert.public_key(public_key)
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(now)
        cert = cert.not_valid_after(now + datetime.timedelta(days=days_valid))
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address(host))]), critical=False)
        cert = cert.sign(private_key._private_key, hashes.SHA512(), default_backend())

        return cls(cert)

    def __init__(self, certificate: x509.Certificate):
        self._certificate = certificate
        self.declared_host = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

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

    def to_json(self):
        return self.to_pem_bytes().decode()

    @classmethod
    def from_json(cls, data):
        return cls.from_pem_bytes(data.encode())

    # FIXME: temporary support for pickling. Remove when we switch to JSON

    def __getstate__(self):
        return self.to_pem_bytes()

    def __setstate__(self, state):
        obj = SSLCertificate.from_pem_bytes(state)
        self._certificate = obj._certificate
        self.declared_host = obj.declared_host


async def fetch_certificate(host: str, port: int) -> SSLCertificate:

    # Do not verify the certificate, it is self-signed
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    stream = await trio.open_ssl_over_tcp_stream(host, port, ssl_context=context)
    await stream.do_handshake()
    certificate_der = stream.getpeercert(True)
    return SSLCertificate.from_der_bytes(certificate_der)
