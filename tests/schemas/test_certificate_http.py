"""HTTP mTLS emission of CertificateAuthProfile: identity, trust and ownership contracts.

Every identity assertion observes a real TLS peer (socket-free handshake or an
actual HTTPX request to a mandatory-mTLS loopback server).
"""
from __future__ import annotations

import asyncio
import errno
import os
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import certifi
import httpx
import pytest

from mountainash_auth_client import CertificateAuthProfile
from mountainash_auth_client.targets import TargetFamily
from tests._error_surfaces import exception_surfaces
from tests._tls import Identity, TLSCase, loopback_server, make_tls_case, peer_common_name

if TYPE_CHECKING:
    from collections.abc import Iterator

PASSPHRASE = "test-passphrase"
PROXY_VARIABLES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", *PROXY_VARIABLES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


@pytest.fixture
def tls_case(tmp_path: Path) -> TLSCase:
    return make_tls_case(tmp_path)


@pytest.fixture
def other_case(tmp_path: Path) -> TLSCase:
    """An unrelated PKI whose root does not sign anything the main server presents."""
    directory = tmp_path / "other"
    directory.mkdir()
    return make_tls_case(directory)


def alice_profile(case: TLSCase) -> CertificateAuthProfile:
    return CertificateAuthProfile(
        CERTIFICATE_PATH=case.alice.chain_path, PRIVATE_KEY_PATH=case.alice.key_path
    )


def hashed_ca_directory(root: Path, ca_path: Path) -> Path:
    directory = root / f"capath-{ca_path.parent.name}"
    directory.mkdir()
    shutil.copy(ca_path, directory / "ca.pem")
    subprocess.run(["openssl", "rehash", str(directory)], check=True, capture_output=True)
    return directory


def certifi_der_certificates() -> set[bytes]:
    text = Path(certifi.where()).read_text(encoding="ascii")
    blocks = text.split("-----END CERTIFICATE-----")
    return {
        ssl.PEM_cert_to_DER_cert(block[block.index("-----BEGIN CERTIFICATE-----"):]
                                 + "-----END CERTIFICATE-----\n")
        for block in blocks
        if "-----BEGIN CERTIFICATE-----" in block
    }


def emit_context(
    case: TLSCase, base: dict[str, Any], profile: CertificateAuthProfile | None = None
) -> ssl.SSLContext:
    out = (profile or alice_profile(case)).emit(TargetFamily.HTTP, base=base)
    context = out["verify"]
    assert isinstance(context, ssl.SSLContext)
    return context


# --- test support: input forms, and the real temporary-file boundary ----------------

FORMS = (
    "combined-path",
    "combined-secret",
    "path+path",
    "path+secret",
    "secret+path",
    "secret+secret",
)


def identity_fields(identity: Identity, form: str, encrypted: bool) -> dict[str, Any]:
    """Profile fields for one of the six source forms; independent of the renderer."""
    key = identity.encrypted_key if encrypted else identity.key
    key_path = identity.encrypted_key_path if encrypted else identity.key_path
    fields: dict[str, Any] = {}
    if form.startswith("combined"):
        if form.endswith("path"):
            fields["CERTIFICATE_PATH"] = (
                identity.encrypted_combined_path if encrypted else identity.combined_path
            )
        else:
            fields["CERTIFICATE"] = (identity.chain + key).decode("ascii")
    else:
        certificate, _, key_source = form.partition("+")
        if certificate == "path":
            fields["CERTIFICATE_PATH"] = identity.chain_path
        else:
            fields["CERTIFICATE"] = identity.chain.decode("ascii")
        if key_source == "path":
            fields["PRIVATE_KEY_PATH"] = key_path
        else:
            fields["PRIVATE_KEY"] = key.decode("ascii")
    if encrypted:
        fields["PASSPHRASE"] = PASSPHRASE
    return fields


def source_fields(directory: Path, name: str, content: bytes, *, secret: bool) -> dict[str, Any]:
    """``NAME`` as a secret, or ``NAME_PATH`` pointing at a file holding *content*."""
    if secret:
        return {name: content.decode("ascii")}
    directory.mkdir(exist_ok=True)
    path = directory / f"{name.lower()}.pem"
    path.write_bytes(content)
    return {f"{name}_PATH": path}


def secret_profile(identity: Identity, encrypted: bool = False) -> CertificateAuthProfile:
    return CertificateAuthProfile(**identity_fields(identity, "secret+secret", encrypted))


def trusted_base(case: TLSCase) -> dict[str, Any]:
    return {"verify": case.client_context, "trust_env": False}


def pem_marker(pem: bytes) -> str:
    """A line from inside a PEM body: present only if the secret itself leaked."""
    return pem.decode("ascii").splitlines()[2]


def secret_markers(case: TLSCase) -> list[str]:
    identities = (case.alice, case.bob)
    return [
        PASSPHRASE,
        "wrong-passphrase",
        *(pem_marker(i.chain) for i in identities),
        *(pem_marker(i.key) for i in identities),
        *(pem_marker(i.encrypted_key) for i in identities),
    ]


@dataclass
class Fault:
    """Fail one stdlib boundary on its ``call``-th use (``unlink``: on every use)."""

    point: str  # mkstemp | write | close | load | unlink
    error: OSError
    call: int = 1


class _FaultingStream:
    """Delegates to the real stream; the real file is still created, written and closed."""

    def __init__(self, stream: Any, observer: TempObserver) -> None:
        self._stream = stream
        self._observer = observer

    def __enter__(self) -> _FaultingStream:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def write(self, data: Any) -> Any:
        error = self._observer.fault_for("write")
        if error is not None:
            raise error
        return self._stream.write(data)

    def close(self) -> None:
        self._stream.close()  # the descriptor really closes, then the OS "reports" failure
        error = self._observer.fault_for("close")
        if error is not None:
            raise error

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class TempObserver:
    """Observe stdlib temporary-file use by one emission, against the real filesystem.

    All temporary material lands in ``root``. ``watch`` wraps ``tempfile.TemporaryDirectory``,
    ``tempfile.mkstemp``, ``os.fdopen``, ``os.unlink`` and ``SSLContext.load_cert_chain`` so every
    call still reaches the real implementation; a ``Fault`` makes exactly one boundary fail.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.directories = 0
        self.files = 0
        self.at_load: list[list[tuple[str, bool, int]]] = []
        self.at_fault: list[tuple[str, bool, int]] = []
        self.fault_hits = 0
        self._fault: Fault | None = None
        self._calls: dict[str, int] = {}

    def snapshot(self) -> list[tuple[str, bool, int]]:
        """(relative path, is_directory, permission bits) of everything under ``root``."""
        return [
            (str(path.relative_to(self.root)), path.is_dir(), stat.S_IMODE(path.lstat().st_mode))
            for path in sorted(self.root.rglob("*"))
        ]

    def fault_for(self, point: str) -> OSError | None:
        self._calls[point] = self._calls.get(point, 0) + 1
        fault = self._fault
        if fault is None or fault.point != point:
            return None
        if point != "unlink" and self._calls[point] != fault.call:
            return None
        if self.fault_hits == 0:
            self.at_fault = self.snapshot()
        self.fault_hits += 1
        error = fault.error
        return type(error)(error.errno, error.strerror, error.filename)

    @contextmanager
    def watch(self, fault: Fault | None = None) -> Iterator[TempObserver]:
        self._fault = fault
        observer = self
        real_mkstemp = tempfile.mkstemp
        real_fdopen = os.fdopen
        real_unlink = os.unlink
        real_load = ssl.SSLContext.load_cert_chain

        class Directory(tempfile.TemporaryDirectory[str]):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                observer.directories += 1
                super().__init__(*args, **kwargs)

        def mkstemp(*args: Any, **kwargs: Any) -> Any:
            error = observer.fault_for("mkstemp")
            if error is not None:
                raise error
            created = real_mkstemp(*args, **kwargs)
            observer.files += 1
            return created

        def fdopen(fd: int, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            stream = real_fdopen(fd, mode, *args, **kwargs)
            return _FaultingStream(stream, observer) if "w" in mode else stream

        def unlink(*args: Any, **kwargs: Any) -> None:
            error = observer.fault_for("unlink")
            if error is not None:
                raise error
            real_unlink(*args, **kwargs)

        def load(context: ssl.SSLContext, certfile: Any, keyfile: Any = None, password: Any = None) -> None:
            observer.at_load.append(observer.snapshot())
            error = observer.fault_for("load")
            if error is not None:
                raise error
            real_load(context, certfile, keyfile, password)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(tempfile, "TemporaryDirectory", Directory)
            patch.setattr(tempfile, "mkstemp", mkstemp)
            patch.setattr(os, "fdopen", fdopen)
            patch.setattr(os, "unlink", unlink)
            patch.setattr(ssl.SSLContext, "load_cert_chain", load)
            yield self


@pytest.fixture
def temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TempObserver:
    """Route every stdlib temporary file/directory under a private, initially empty root."""
    root = tmp_path / "scratch"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return TempObserver(root)


@pytest.mark.parametrize("source", ["certificate", "key"])
def test_path_source_wins_over_its_malformed_secret(tls_case, source):
    fields: dict[str, Any] = {
        "CERTIFICATE_PATH": tls_case.alice.chain_path,
        "PRIVATE_KEY_PATH": tls_case.alice.key_path,
    }
    fields["CERTIFICATE" if source == "certificate" else "PRIVATE_KEY"] = "not a pem document\n"
    out = CertificateAuthProfile(**fields).emit(TargetFamily.HTTP, base=trusted_base(tls_case))
    assert peer_common_name(out["verify"], tls_case.server_context) == "alice"


@pytest.mark.parametrize("source", ["certificate", "key"])
def test_missing_path_does_not_fall_back_to_its_secret(tls_case, tmp_path, temp, source):
    alice = tls_case.alice
    missing = tmp_path / "missing-input.pem"
    fields: dict[str, Any] = {
        "CERTIFICATE_PATH": alice.chain_path,
        "PRIVATE_KEY_PATH": alice.key_path,
    }
    if source == "certificate":
        fields |= {"CERTIFICATE_PATH": missing, "CERTIFICATE": alice.chain.decode("ascii")}
    else:
        fields |= {"PRIVATE_KEY_PATH": missing, "PRIVATE_KEY": alice.key.decode("ascii")}

    with temp.watch(), pytest.raises(ValueError) as raised:
        CertificateAuthProfile(**fields).emit(TargetFamily.HTTP, base=trusted_base(tls_case))

    assert missing.name not in exception_surfaces(raised.value)
    assert temp.files == 0  # the valid secret was never substituted for the missing path
    assert temp.snapshot() == []


@pytest.mark.parametrize("key_secret", [False, True], ids=["key-path", "key-secret"])
@pytest.mark.parametrize("combined_secret", [False, True], ids=["combined-path", "combined-secret"])
@pytest.mark.parametrize(
    ("embedded", "explicit", "authenticates"),
    [("bob", "alice", True), ("alice", "bob", False)],
    ids=["explicit-key-overrides-wrong-embedded", "mismatched-explicit-key-fails"],
)
def test_explicit_key_beats_key_embedded_in_combined_pem(
    tls_case, tmp_path, temp, embedded, explicit, authenticates, combined_secret, key_secret
):
    owners = {"alice": tls_case.alice, "bob": tls_case.bob}
    inputs = tmp_path / "inputs"
    fields = source_fields(
        inputs,
        "CERTIFICATE",
        tls_case.alice.chain + owners[embedded].key,
        secret=combined_secret,
    ) | source_fields(inputs, "PRIVATE_KEY", owners[explicit].key, secret=key_secret)
    profile = CertificateAuthProfile(**fields)

    if authenticates:
        out = profile.emit(TargetFamily.HTTP, base=trusted_base(tls_case))
        assert peer_common_name(out["verify"], tls_case.server_context) == "alice"
    else:
        with temp.watch(), pytest.raises(ValueError):
            profile.emit(TargetFamily.HTTP, base=trusted_base(tls_case))
        assert temp.snapshot() == []


# --- secret hygiene ---------------------------------------------------------------


def test_secret_fields_do_not_appear_in_repr(tls_case):
    alice = tls_case.alice
    profile = CertificateAuthProfile(
        CERTIFICATE=alice.chain.decode("ascii"),
        PRIVATE_KEY=alice.encrypted_key.decode("ascii"),
        PASSPHRASE=PASSPHRASE,
    )
    assert profile.CERTIFICATE.get_secret_value() == alice.chain.decode("ascii")  # it is held
    shown = [
        repr(profile),
        str(profile),
        repr(profile.CERTIFICATE),
        str(profile.CERTIFICATE),
        repr(profile.PRIVATE_KEY),
        repr(profile.PASSPHRASE),
    ]
    for marker in ("-----BEGIN", pem_marker(alice.chain), pem_marker(alice.encrypted_key), PASSPHRASE):
        for text in shown:
            assert marker not in text


# --- temporary secret material: lifetime and permissions -----------------------------


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("encrypted", [False, True], ids=["plain", "encrypted"])
def test_identity_and_private_material_lifetime(tls_case, temp, form, encrypted):
    with temp.watch():
        out = CertificateAuthProfile(**identity_fields(tls_case.alice, form, encrypted)).emit(
            TargetFamily.HTTP, base=trusted_base(tls_case)
        )

    materialized_at_load = any(not is_directory for _, is_directory, _ in temp.at_load[0])
    if "secret" in form:
        assert temp.files > 0
        assert materialized_at_load  # real material existed when the loader consumed it
        entries = temp.at_load[0]
        assert {is_directory for _, is_directory, _ in entries} == {True, False}
        if sys.platform != "win32":
            for relative, _, mode in entries:
                assert mode & 0o077 == 0, f"{relative} is accessible beyond its owner: {mode:o}"
    else:
        assert temp.directories == 0 and temp.files == 0  # path-only inputs allocate nothing
        assert temp.at_load[0] == []
    assert temp.snapshot() == []
    assert peer_common_name(out["verify"], tls_case.server_context) == "alice"



# --- invalid identity input ------------------------------------------------------------

ERROR_CASES = (
    "missing-certificate",
    "key-missing-from-certificate",
    "wrong-passphrase",
    "missing-passphrase",
    "malformed-pem",
    "mismatched-key",
)


def failing_fields(case: str, tls_case: TLSCase, inputs: Path, secret: bool) -> dict[str, Any]:
    alice, bob = tls_case.alice, tls_case.bob

    def certificate(content: bytes) -> dict[str, Any]:
        return source_fields(inputs, "CERTIFICATE", content, secret=secret)

    def key(content: bytes) -> dict[str, Any]:
        return source_fields(inputs, "PRIVATE_KEY", content, secret=secret)

    if case == "missing-certificate":
        return key(alice.key)
    if case == "key-missing-from-certificate":
        return certificate(alice.chain)
    if case == "wrong-passphrase":
        return certificate(alice.chain) | key(alice.encrypted_key) | {"PASSPHRASE": "wrong-passphrase"}
    if case == "missing-passphrase":
        return certificate(alice.chain) | key(alice.encrypted_key)
    if case == "malformed-pem":
        return certificate(b"not a certificate\n") | key(alice.key)
    assert case == "mismatched-key"
    return certificate(alice.chain) | key(bob.key)


@pytest.mark.parametrize("secret", [False, True], ids=["path", "secret"])
@pytest.mark.parametrize("case", ERROR_CASES)
def test_invalid_identity_fails_safely_and_leaves_no_material(tls_case, tmp_path, temp, case, secret):
    fields = failing_fields(case, tls_case, tmp_path / "inputs", secret)

    with temp.watch(), pytest.raises(ValueError) as raised:
        CertificateAuthProfile(**fields).emit(TargetFamily.HTTP, base=trusted_base(tls_case))

    surfaces = exception_surfaces(raised.value)
    for marker in secret_markers(tls_case):
        assert marker not in surfaces
    assert str(tmp_path) not in surfaces  # neither input nor temporary file locations
    if case != "missing-certificate":
        assert (temp.files > 0) == secret  # secret inputs really were materialized, then removed
    assert temp.snapshot() == []


@pytest.mark.parametrize("failure", ["missing-ca-file", "invalid-verify-type"])
def test_trust_failure_surfaces_before_any_secret_is_written(tls_case, tmp_path, temp, failure):
    missing_ca = tmp_path / "no-such-ca.pem"
    verify, expected = (
        (str(missing_ca), ValueError) if failure == "missing-ca-file" else (42, TypeError)
    )
    with temp.watch(), pytest.raises(expected) as raised:
        secret_profile(tls_case.alice).emit(
            TargetFamily.HTTP, base={"verify": verify, "trust_env": False}
        )

    surfaces = exception_surfaces(raised.value)
    assert missing_ca.name not in surfaces
    for marker in secret_markers(tls_case):
        assert marker not in surfaces
    assert temp.directories == 0 and temp.files == 0


# --- faults at the real temporary-file boundary ---------------------------------------

FAULT_FILENAME = "/FAULT_PATH_MARKER/denied"


@pytest.mark.parametrize(
    ("point", "call", "files_at_fault", "number"),
    [
        ("mkstemp", 1, 0, errno.ENOSPC),
        ("mkstemp", 2, 1, errno.ENOSPC),
        ("write", 1, 1, errno.ENOSPC),
        ("write", 2, 2, errno.ENOSPC),
        ("close", 1, 1, errno.EIO),
        ("close", 2, 2, errno.EIO),
        ("load", 1, 2, errno.EIO),
    ],
    ids=lambda value: str(value) if isinstance(value, str) else None,
)
def test_failure_after_material_exists_removes_it_and_exposes_nothing(
    tls_case, tmp_path, temp, point, call, files_at_fault, number
):
    fault = Fault(point, OSError(number, os.strerror(number), FAULT_FILENAME), call)
    with temp.watch(fault), pytest.raises(ValueError) as raised:
        secret_profile(tls_case.alice).emit(TargetFamily.HTTP, base=trusted_base(tls_case))

    assert temp.fault_hits == 1
    # Real directory/files existed at the instant of failure, and are gone afterwards.
    present = [entry for entry in temp.at_fault if not entry[1]]
    assert len(present) == files_at_fault
    assert any(is_directory for _, is_directory, _ in temp.at_fault)
    assert temp.snapshot() == []

    surfaces = exception_surfaces(raised.value)
    assert "FAULT_PATH_MARKER" not in surfaces
    assert str(tmp_path) not in surfaces
    for marker in secret_markers(tls_case):
        assert marker not in surfaces
    cause = raised.value.__cause__
    assert isinstance(cause, OSError) and cause.errno == number and cause.filename is None
    assert raised.value.__context__ is None


def test_deletion_refusal_fails_visibly_without_unsafe_context(tls_case, tmp_path, temp):
    refusal = PermissionError(errno.EACCES, "Permission denied", FAULT_FILENAME)
    try:
        with temp.watch(Fault("unlink", refusal)), pytest.raises(ValueError) as raised:
            secret_profile(tls_case.alice).emit(TargetFamily.HTTP, base=trusted_base(tls_case))

        assert temp.fault_hits >= 1
        # The refusal was real: material is still there, and emit did not report success.
        assert any(not is_directory for _, is_directory, _ in temp.snapshot())
        surfaces = exception_surfaces(raised.value)
        assert "FAULT_PATH_MARKER" not in surfaces
        assert str(tmp_path) not in surfaces
        for marker in secret_markers(tls_case):
            assert marker not in surfaces
        cause = raised.value.__cause__
        assert isinstance(cause, OSError) and cause.errno == errno.EACCES and cause.filename is None
    finally:  # restore access: the test removes its own residue
        for child in temp.root.iterdir():
            shutil.rmtree(child)


# --- ownership of the consumer's base -----------------------------------------


def test_raw_context_is_rejected_and_left_unmodified(tls_case):
    context = tls_case.client_context()
    with pytest.raises(TypeError):
        alice_profile(tls_case).emit(
            TargetFamily.HTTP, base={"verify": context, "trust_env": False}
        )
    # An identity loaded into the rejected context would let this handshake succeed.
    with pytest.raises(ssl.SSLError):
        peer_common_name(context, tls_case.server_context)


def test_legacy_cert_in_base_cannot_replace_profile_identity(tls_case):
    bob_cert = (str(tls_case.bob.chain_path), str(tls_case.bob.key_path))
    base: dict[str, Any] = {
        "verify": tls_case.client_context,
        "trust_env": False,
        "cert": bob_cert,
        "headers": {"X-Caller": "kept"},
        "timeout": 7.5,
    }
    out = alice_profile(tls_case).emit(TargetFamily.HTTP, base=base)

    assert "cert" not in out
    assert out["headers"] == {"X-Caller": "kept"}
    assert out["timeout"] == 7.5
    assert base["cert"] is bob_cert
    assert base["verify"] == tls_case.client_context
    assert base["headers"] == {"X-Caller": "kept"}

    with loopback_server(tls_case.server_context) as url, httpx.Client(**out) as client:
        response = client.get(url)
    assert response.status_code == 200
    assert response.text.strip() == "alice"


# --- trust selection -----------------------------------------------------------


@pytest.mark.parametrize("explicit", [False, True], ids=["omitted", "verify-true"])
def test_default_trust_is_public_bundle_and_rejects_private_ca(tls_case, explicit):
    base: dict[str, Any] = {"trust_env": False}
    if explicit:
        base["verify"] = True
    context = emit_context(tls_case, base)

    assert set(context.get_ca_certs(binary_form=True)) == certifi_der_certificates()
    with pytest.raises(ssl.SSLError):
        peer_common_name(context, tls_case.server_context)


def test_verify_false_accepts_private_ca_peer(tls_case):
    context = emit_context(tls_case, {"verify": False, "trust_env": False})
    assert peer_common_name(context, tls_case.server_context) == "alice"


def test_verify_ca_file_authenticates_and_wrong_ca_fails(tls_case, other_case):
    trusted = emit_context(tls_case, {"verify": str(tls_case.ca_path), "trust_env": False})
    assert peer_common_name(trusted, tls_case.server_context) == "alice"

    wrong = emit_context(tls_case, {"verify": str(other_case.ca_path), "trust_env": False})
    with pytest.raises(ssl.SSLError):
        peer_common_name(wrong, tls_case.server_context)


def test_verify_ca_directory_authenticates_and_wrong_ca_fails(tls_case, other_case, tmp_path):
    good = hashed_ca_directory(tmp_path, tls_case.ca_path)
    bad = hashed_ca_directory(tmp_path, other_case.ca_path)

    trusted = emit_context(tls_case, {"verify": str(good), "trust_env": False})
    assert peer_common_name(trusted, tls_case.server_context) == "alice"

    wrong = emit_context(tls_case, {"verify": str(bad), "trust_env": False})
    with pytest.raises(ssl.SSLError):
        peer_common_name(wrong, tls_case.server_context)


# --- environment trust ----------------------------------------------------------


@pytest.mark.parametrize("explicit", [False, True], ids=["omitted", "verify-true"])
def test_env_ca_file_and_directory_are_honored_when_trust_env(
    tls_case, tmp_path, monkeypatch, explicit
):
    base: dict[str, Any] = {"trust_env": True}
    if explicit:
        base["verify"] = True

    monkeypatch.setenv("SSL_CERT_FILE", str(tls_case.ca_path))
    from_file = emit_context(tls_case, base)
    assert peer_common_name(from_file, tls_case.server_context) == "alice"

    monkeypatch.delenv("SSL_CERT_FILE")
    monkeypatch.setenv("SSL_CERT_DIR", str(hashed_ca_directory(tmp_path, tls_case.ca_path)))
    from_directory = emit_context(tls_case, base)
    assert peer_common_name(from_directory, tls_case.server_context) == "alice"


def test_env_ca_file_takes_precedence_over_directory(
    tls_case, other_case, tmp_path, monkeypatch
):
    good_directory = hashed_ca_directory(tmp_path, tls_case.ca_path)
    bad_directory = hashed_ca_directory(tmp_path, other_case.ca_path)
    base: dict[str, Any] = {"verify": True, "trust_env": True}

    monkeypatch.setenv("SSL_CERT_FILE", str(tls_case.ca_path))
    monkeypatch.setenv("SSL_CERT_DIR", str(bad_directory))
    file_wins = emit_context(tls_case, base)
    assert peer_common_name(file_wins, tls_case.server_context) == "alice"

    monkeypatch.setenv("SSL_CERT_FILE", str(other_case.ca_path))
    monkeypatch.setenv("SSL_CERT_DIR", str(good_directory))
    wrong_file_wins = emit_context(tls_case, base)
    with pytest.raises(ssl.SSLError):
        peer_common_name(wrong_file_wins, tls_case.server_context)


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_env_ca_is_not_consulted_when_trust_env_false(
    tls_case, tmp_path, monkeypatch, variable
):
    location = (
        tls_case.ca_path
        if variable == "SSL_CERT_FILE"
        else hashed_ca_directory(tmp_path, tls_case.ca_path)
    )
    monkeypatch.setenv(variable, str(location))
    context = emit_context(tls_case, {"verify": True, "trust_env": False})
    with pytest.raises(ssl.SSLError):
        peer_common_name(context, tls_case.server_context)


# --- factory-supplied TLS policy --------------------------------------------------


def test_factory_tls_version_policy_survives_identity_loading(tls_case):
    tls_case.server_context.maximum_version = ssl.TLSVersion.TLSv1_2

    def permissive() -> ssl.SSLContext:
        return tls_case.client_context()

    def tls13_only() -> ssl.SSLContext:
        context = tls_case.client_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return context

    compatible = emit_context(tls_case, {"verify": permissive, "trust_env": False})
    assert peer_common_name(compatible, tls_case.server_context) == "alice"

    restricted = emit_context(tls_case, {"verify": tls13_only, "trust_env": False})
    with pytest.raises(ssl.SSLError):
        peer_common_name(restricted, tls_case.server_context)


def test_hostname_mismatch_is_a_verification_failure_not_missing_identity(tls_case):
    out = alice_profile(tls_case).emit(
        TargetFamily.HTTP, base={"verify": tls_case.client_context, "trust_env": False}
    )
    with loopback_server(tls_case.server_context) as url:
        with httpx.Client(**out) as client:
            assert client.get(url).text.strip() == "alice"  # control: right name works
        wrong_name = url.replace("127.0.0.1", "localhost")
        assert wrong_name != url
        with httpx.Client(**out) as client, pytest.raises(httpx.ConnectError) as raised:
            client.get(wrong_name)
    assert "CERTIFICATE_VERIFY_FAILED" in str(raised.value)


def test_factory_emissions_carry_independent_identities(tls_case):
    alice = emit_context(tls_case, {"verify": tls_case.client_context, "trust_env": False})
    bob_profile = CertificateAuthProfile(
        CERTIFICATE_PATH=tls_case.bob.chain_path, PRIVATE_KEY_PATH=tls_case.bob.key_path
    )
    bob = emit_context(
        tls_case, {"verify": tls_case.client_context, "trust_env": False}, bob_profile
    )

    assert alice is not bob
    assert peer_common_name(bob, tls_case.server_context) == "bob"
    # Loading Bob must not have changed Alice's context.
    assert peer_common_name(alice, tls_case.server_context) == "alice"
    # A client the profile never touched is rejected by the mandatory-mTLS server.
    with pytest.raises(ssl.SSLError):
        peer_common_name(tls_case.client_context(), tls_case.server_context)


# --- factory failures ---------------------------------------------------------------


@pytest.mark.parametrize(
    "native",
    [ValueError("FACTORY_SECRET"), OSError(errno.EIO, "FACTORY_SECRET")],
    ids=["ValueError", "OSError"],
)
def test_failing_factory_raises_safe_value_error(tls_case, temp, native):
    calls: list[None] = []

    def factory() -> ssl.SSLContext:
        calls.append(None)
        raise native

    with temp.watch(), pytest.raises(ValueError) as raised:
        secret_profile(tls_case.alice).emit(
            TargetFamily.HTTP, base={"verify": factory, "trust_env": False}
        )
    assert len(calls) == 1  # the factory itself failed, not some unrelated rejection
    assert "FACTORY_SECRET" not in exception_surfaces(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert temp.directories == 0 and temp.files == 0  # identity never materialized


@pytest.mark.parametrize(
    "result",
    [None, "not-a-context", object(), b"ca-bytes"],
    ids=["None", "str", "object", "bytes"],
)
def test_factory_must_return_a_context(tls_case, temp, result):
    calls: list[None] = []

    def factory() -> Any:
        calls.append(None)
        return result

    with temp.watch(), pytest.raises(TypeError):
        secret_profile(tls_case.alice).emit(
            TargetFamily.HTTP, base={"verify": factory, "trust_env": False}
        )
    assert len(calls) == 1  # the factory's return value, not the target, was rejected
    assert temp.directories == 0 and temp.files == 0


# --- real HTTPX use of an emission ------------------------------------------------------


def test_emitted_context_authenticates_clients_recreated_after_material_is_gone(tls_case, temp):
    with temp.watch():
        out = secret_profile(tls_case.alice, encrypted=True).emit(
            TargetFamily.HTTP, base=trusted_base(tls_case)
        )
    assert temp.files > 0
    assert temp.snapshot() == []

    with loopback_server(tls_case.server_context) as url:
        for _ in range(2):
            with httpx.Client(**out) as client:
                response = client.get(url)
            assert response.status_code == 200
            assert response.text.strip() == "alice"
        # Control: a client the profile never touched is rejected by the same server.
        with pytest.raises(httpx.HTTPError), httpx.Client(verify=tls_case.client_context()) as bare:
            bare.get(url)


def test_async_client_authenticates_from_an_in_memory_emission(tls_case):
    out = CertificateAuthProfile(
        **identity_fields(tls_case.alice, "secret+path", encrypted=True)
    ).emit(TargetFamily.HTTP, base=trusted_base(tls_case))

    async def fetch(url: str) -> httpx.Response:
        async with httpx.AsyncClient(**out) as client:
            return await client.get(url)

    with loopback_server(tls_case.server_context) as url:
        response = asyncio.run(fetch(url))
    assert response.status_code == 200
    assert response.text.strip() == "alice"
