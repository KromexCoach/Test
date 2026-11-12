"""Vérifie, par de vraies poignées de main TLS, que le certificat du serveur est contrôlé."""

import datetime
import ipaddress
import socket
import ssl
import threading
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from iam_ad.directory import DirectoryUnavailableError
from iam_ad.directory.ldap_ad import LdapDirectory
from tests.conftest import make_settings
from tests.test_config import LDAP

# ldap3 ne referme pas lui-même la connexion qu'il vient de refuser : le ramasse-miettes s'en
# charge, ce que Python signale par un avertissement sans conséquence ici.
pytestmark = pytest.mark.filterwarnings(
    "ignore::ResourceWarning", "ignore::pytest.PytestUnraisableExceptionWarning"
)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(subject, issuer, public_key, signing_key, *, ca=False, san=None):
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False,
        ).add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def _pem(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Une autorité de test et des certificats serveur au bon et au mauvais nom d'hôte."""
    directory = tmp_path_factory.mktemp("pki")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _certificate("AC de test", "AC de test", ca_key.public_key(), ca_key, ca=True)
    (directory / "ca.pem").write_bytes(_pem(ca))

    paths = {"ca": directory / "ca.pem"}
    sans = {
        "valid": [x509.DNSName("localhost")],
        # Même machine, mais désignée par son adresse IP et non par son nom.
        "ip_only": [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
        "wrong_host": [x509.DNSName("autre-serveur.exemple.be")],
    }
    for label, san in sans.items():
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _certificate(label, "AC de test", key.public_key(), ca_key, san=san)
        (directory / f"{label}.pem").write_bytes(
            _pem(certificate)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        paths[label] = directory / f"{label}.pem"
    return paths


class TlsServer:
    """Serveur TLS minimal : note si une poignée de main a abouti, puis raccroche."""

    def __init__(self, certificate_path, minimum=None, maximum=None) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate_path)
        if minimum:
            context.minimum_version = minimum
        if maximum:
            context.maximum_version = maximum
        self._context = context
        self._socket = socket.create_server(("127.0.0.1", 0))
        self.port = self._socket.getsockname()[1]
        self.handshake_completed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        # Plusieurs connexions possibles : ldap3 sonde d'abord le port quand le nom du serveur
        # correspond à plusieurs adresses (IPv4 et IPv6).
        while True:
            try:
                raw, _ = self._socket.accept()
            except OSError:
                return
            with raw:
                raw.settimeout(5)
                try:
                    with self._context.wrap_socket(raw, server_side=True):
                        self.handshake_completed = True
                except (ssl.SSLError, OSError):
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        self._thread.join(timeout=5)


def connect(port: int, ca_file=None, host: str = "localhost") -> Exception:
    settings = make_settings(
        **{**LDAP, "ad_servers": host, "ad_port": port, "ad_timeout_seconds": 3},
        ad_ca_cert_file=ca_file,
    )
    with pytest.raises(DirectoryUnavailableError) as error:
        LdapDirectory(settings).check()
    return error.value.__cause__


def test_trusted_certificate_with_matching_name_is_accepted(pki):
    with TlsServer(pki["valid"]) as server:
        cause = connect(server.port, pki["ca"])
    # La poignée de main aboutit ; l'échec vient ensuite de l'absence de réponse LDAP.
    assert server.handshake_completed
    assert "certificate" not in str(cause).lower()


def test_certificate_from_unknown_authority_is_refused(pki):
    with TlsServer(pki["valid"]) as server:
        cause = connect(server.port, ca_file=None)
    assert not server.handshake_completed
    assert "CERTIFICATE_VERIFY_FAILED" in str(cause)


def test_certificate_for_another_host_is_refused(pki):
    with TlsServer(pki["wrong_host"]) as server:
        cause = connect(server.port, pki["ca"])
    assert "doesn't match" in str(cause)


def test_server_addressed_by_ip_is_refused(pki):
    # Les contrôleurs de domaine se désignent par leur nom DNS (IAM_AD_SERVERS), jamais par IP.
    with TlsServer(pki["ip_only"]) as server:
        cause = connect(server.port, pki["ca"], host="127.0.0.1")
    assert "doesn't match" in str(cause)


def test_tls_versions_below_1_2_are_refused(pki):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            server = TlsServer(pki["valid"], ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
    except (ValueError, ssl.SSLError):
        pytest.skip("la bibliothèque TLS locale ne sait plus servir TLS 1.0/1.1")
    with server:
        cause = connect(server.port, pki["ca"])
    assert not server.handshake_completed
    assert "certificate" not in str(cause).lower()
