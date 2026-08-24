"""
Regression tests for H-9, H-18 and M-18: secrets must not reach the log.

The application log is not a low-value artefact here: LOG_FILE keeps five rotated
copies and admins can stream it live over WebSocket. Three separate secrets used to
land in it — the V2 authentication line (client token + HMAC digest, enough to replay
the handshake and to brute-force the vehicle password offline), the auto-provisioning
key, and password-reset tokens carried in the URL path.
"""

import ast
import logging
import pathlib

import pytest

from app.logging_config import RedactingFilter

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _record(msg: str, *args) -> logging.LogRecord:
    return logging.LogRecord("test", logging.INFO, __file__, 1, msg, args or None, None)


# --- H-18: URL-borne secrets in the access log ----------------------------------

@pytest.mark.parametrize("line, secret", [
    ('127.0.0.1:1 - "GET /ws?ticket=ws-ticket-SECRETVALUE HTTP/1.1" 101', "SECRETVALUE"),
    ('127.0.0.1:1 - "GET /reset-password/RESETTOKENSECRET HTTP/1.1" 200', "RESETTOKENSECRET"),
    ('127.0.0.1:1 - "GET /verify/VERIFYTOKENSECRET HTTP/1.1" 200', "VERIFYTOKENSECRET"),
    ('127.0.0.1:1 - "POST /x?token=ANOTHERSECRET&y=1 HTTP/1.1" 200', "ANOTHERSECRET"),
])
def test_url_secrets_are_redacted(line, secret):
    record = _record(line)
    RedactingFilter().filter(record)
    assert secret not in record.getMessage()
    assert "<redacted>" in record.getMessage()


def test_redaction_also_covers_lazy_format_arguments():
    """uvicorn.access logs via %-args, not a pre-formatted string."""
    record = _record("%s - %s", "127.0.0.1", "GET /reset-password/LAZYSECRET HTTP/1.1")
    RedactingFilter().filter(record)
    assert "LAZYSECRET" not in record.getMessage()


def test_ordinary_paths_are_untouched():
    record = _record('127.0.0.1:1 - "GET /vehicles/ABC123 HTTP/1.1" 200')
    RedactingFilter().filter(record)
    assert "/vehicles/ABC123" in record.getMessage()


def test_filter_never_drops_records():
    """A logging filter returning False would silently discard the entry."""
    record = _record("anything")
    assert RedactingFilter().filter(record) is True


# --- H-9 / M-18: the V2 handshake and AP key must not be logged verbatim ---------

def _string_constants(path: pathlib.Path) -> list[str]:
    tree = ast.parse(path.read_text())
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_v2_auth_module_does_not_log_the_raw_line():
    """
    The auth handler receives the full credential line; logging repr(line) publishes
    the client token and HMAC digest. Guard against it being reintroduced.
    """
    source = (REPO_ROOT / "app" / "protocols" / "v2" / "auth.py").read_text()
    assert "repr(line" not in source, (
        "logging the raw V2 auth line exposes the client token and HMAC digest"
    )


def test_v2_auth_module_does_not_log_the_client_token_variable():
    source = (REPO_ROOT / "app" / "protocols" / "v2" / "auth.py").read_text()
    for fragment in ("{client_token}", "{client_digest_b64}", "{ap_key}"):
        assert fragment not in source, f"{fragment} interpolated into a log message"
