"""Test-only TLS support: certificate generation, MemoryBIO oracle, loopback server.

Nothing here is a production seam. Key material is generated at runtime and
written only under the caller's pytest ``tmp_path``.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from socket import socket

PASSPHRASE = b"test-passphrase"
_SOCKET_TIMEOUT = 5.0


@dataclass
class Identity:
    chain: bytes
    key: bytes
    encrypted_key: bytes
    chain_path: Path
    key_path: Path
    encrypted_key_path: Path
    combined_path: Path
    encrypted_combined_path: Path


@dataclass
class TLSCase:
    ca_path: Path
    server_context: ssl.SSLContext
    alice: Identity
    bob: Identity

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=self.ca_path)


@dataclass
class _Issued:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _issue(
    common_name: str,
    *,
    issuer: _Issued | None,
    ca: bool,
    path_length: int | None = None,
    server: bool = False,
    client: bool = False,
) -> _Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signing_key = issuer.key if issuer is not None else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()),
            critical=False,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        ).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
    if client:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    return _Issued(key=key, cert=builder.sign(signing_key, hashes.SHA256()))


def _private_pem(key: ec.EllipticCurvePrivateKey, *, encrypted: bool) -> bytes:
    algorithm: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(PASSPHRASE)
        if encrypted
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm
    )


def _identity(
    directory: Path, name: str, leaf: _Issued, intermediate: _Issued
) -> Identity:
    directory.mkdir(parents=True, exist_ok=True)
    chain = leaf.pem + intermediate.pem
    key = _private_pem(leaf.key, encrypted=False)
    encrypted_key = _private_pem(leaf.key, encrypted=True)
    paths = Identity(
        chain=chain,
        key=key,
        encrypted_key=encrypted_key,
        chain_path=directory / f"{name}-chain.pem",
        key_path=directory / f"{name}.key",
        encrypted_key_path=directory / f"{name}-encrypted.key",
        combined_path=directory / f"{name}-combined.pem",
        encrypted_combined_path=directory / f"{name}-encrypted-combined.pem",
    )
    _write_private(paths.chain_path, chain)
    _write_private(paths.key_path, key)
    _write_private(paths.encrypted_key_path, encrypted_key)
    _write_private(paths.combined_path, chain + key)
    _write_private(paths.encrypted_combined_path, chain + encrypted_key)
    return paths


def make_tls_case(tmp_path: Path) -> TLSCase:
    """Create root -> intermediate -> {server, alice, bob} under ``tmp_path``."""
    root = _issue("Test Root CA", issuer=None, ca=True, path_length=1)
    intermediate = _issue("Test Intermediate CA", issuer=root, ca=True, path_length=0)
    server = _issue("127.0.0.1", issuer=intermediate, ca=False, server=True)

    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_bytes(root.pem)

    server_chain = tmp_path / "server-chain.pem"
    server_key = tmp_path / "server.key"
    server_chain.write_bytes(server.pem + intermediate.pem)
    _write_private(server_key, _private_pem(server.key, encrypted=False))

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_cert_chain(server_chain, server_key)
    server_context.load_verify_locations(cafile=ca_path)

    identities = tmp_path / "identities"
    alice = _identity(
        identities, "alice", _issue("alice", issuer=intermediate, ca=False, client=True), intermediate
    )
    bob = _identity(
        identities, "bob", _issue("bob", issuer=intermediate, ca=False, client=True), intermediate
    )
    return TLSCase(ca_path=ca_path, server_context=server_context, alice=alice, bob=bob)


def _common_name(peer: Any) -> str:
    for row in peer["subject"]:
        for field, value in row:
            if field == "commonName":
                return str(value)
    raise AssertionError("peer certificate has no commonName")


def peer_common_name(client_context: ssl.SSLContext, server_context: ssl.SSLContext) -> str:
    """Complete a socket-free mTLS handshake and return the server-observed client CN."""
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname="127.0.0.1")
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    done = [False, False]
    for _ in range(100):
        for index, endpoint in enumerate((client, server)):
            if not done[index]:
                try:
                    endpoint.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
        for outbound, inbound in ((client_out, server_in), (server_out, client_in)):
            if outbound.pending:
                inbound.write(outbound.read())
        if all(done):
            peer = server.getpeercert()
            assert peer is not None
            return _common_name(peer)
    raise AssertionError("local TLS handshake did not complete")


class _Handler(BaseHTTPRequestHandler):
    timeout = _SOCKET_TIMEOUT

    def setup(self) -> None:
        # Handshake here (worker thread) so a failing client never blocks accept().
        self.request.settimeout(_SOCKET_TIMEOUT)
        self.request.do_handshake()
        super().setup()

    def do_GET(self) -> None:
        peer = self.request.getpeercert()
        body = _common_name(peer).encode("ascii") if peer else b""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return None


class _Server(ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self._tls_context = context
        self.timeout = _SOCKET_TIMEOUT

    def get_request(self) -> tuple[socket, Any]:
        raw, address = self.socket.accept()
        raw.settimeout(_SOCKET_TIMEOUT)
        wrapped = self._tls_context.wrap_socket(
            raw, server_side=True, do_handshake_on_connect=False
        )
        return wrapped, address

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Rejected or aborted handshakes are expected in negative controls.
        return None


@contextmanager
def loopback_server(context: ssl.SSLContext) -> Iterator[str]:
    """Serve HTTPS on 127.0.0.1:<ephemeral> under ``context``; GET returns the peer CN."""
    server = _Server(context)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/"
    finally:
        try:
            server.shutdown()
        finally:
            server.server_close()
            thread.join(timeout=_SOCKET_TIMEOUT)
