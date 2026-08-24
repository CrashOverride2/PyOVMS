"""
Hardening from the pre-publication review (2026-08-08).

Three findings, none of them exploitable on their own, all of them the kind of thing
that is cheaper to close before the source is public than to argue about afterwards:

  P-1  The session cookie reader accepted the unprefixed `access_token` alongside
       `__Host-access_token` on every deployment. The prefix exists precisely so that a
       sibling subdomain cannot write the cookie; accepting the plain name over HTTPS
       handed that back and left session fixation open. The unprefixed name is only
       needed where the prefix cannot be used at all — the plain-HTTP test server.

  P-2  The SSRF guard resolved the hostname and then let requests resolve it a second
       time, so a host whose DNS the attacker controls could answer once with a public
       address and once with 127.0.0.1. Plain-HTTP requests now go to the address that
       was actually vetted. HTTPS is left alone on purpose — see _pin_outbound_url().

  P-3  A password reset token whose expiry column was NULL skipped the expiry branch
       entirely, i.e. never expired. Unreachable through the current write path, which
       is exactly why it would have gone unnoticed if it ever became reachable.
"""

import datetime
import types

import pytest
from starlette.requests import Request

from app import dependencies, notifications
from app.dependencies import _get_access_token
# The guard and the pinning live in the leaf module now; `notifications` still
# re-exports both, so the assertions below exercise the same objects either way.
from app.notifications import outbound
from app.routers.ui.auth import _reset_token_is_expired

# Globally routable, and it has to be: the guard rejects the RFC 5737 documentation
# ranges too, since those are not reachable either.
_PUBLIC_IP = "93.184.216.34"


def _request(scheme: str, cookie: str) -> Request:
    """A minimal request carrying one Cookie header."""
    return Request({
        "type": "http",
        "method": "GET",
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"cookie", cookie.encode())],
        "server": ("testserver", 443 if scheme == "https" else 80),
        "client": ("203.0.113.9", 1234),
    })


# ---------------------------------------------------------------------------
# P-1 — the unprefixed cookie is for the plain-HTTP test server only
# ---------------------------------------------------------------------------

def test_host_prefixed_cookie_is_used_over_https():
    request = _request("https", "__Host-access_token=Bearer real")
    assert _get_access_token(request) == "Bearer real"


def test_unprefixed_cookie_is_ignored_over_https(monkeypatch):
    """
    The whole point of P-1: a subdomain can set `access_token` for the parent domain,
    but never `__Host-access_token`. Over HTTPS the plain name must not be a way in.
    """
    monkeypatch.setattr(dependencies.settings, "FORCE_SECURE_COOKIES", False, raising=False)
    request = _request("https", "access_token=Bearer attacker-chosen")
    assert _get_access_token(request) is None


def test_unprefixed_cookie_still_works_on_plain_http(monkeypatch):
    """The local test server has no HTTPS, so __Host- cannot be set there at all."""
    monkeypatch.setattr(dependencies.settings, "FORCE_SECURE_COOKIES", False, raising=False)
    request = _request("http", "access_token=Bearer local-dev")
    assert _get_access_token(request) == "Bearer local-dev"


def test_force_secure_cookies_rejects_the_unprefixed_name_even_on_http(monkeypatch):
    """
    FORCE_SECURE_COOKIES is what the login routes key off when they choose the cookie
    name, so the reader has to agree with them, scheme notwithstanding.
    """
    monkeypatch.setattr(dependencies.settings, "FORCE_SECURE_COOKIES", True, raising=False)
    request = _request("http", "access_token=Bearer stale")
    assert _get_access_token(request) is None


def test_prefixed_cookie_wins_when_both_are_present(monkeypatch):
    """An injected plain cookie must not shadow the real one."""
    monkeypatch.setattr(dependencies.settings, "FORCE_SECURE_COOKIES", False, raising=False)
    request = _request("http", "access_token=Bearer injected; __Host-access_token=Bearer real")
    assert _get_access_token(request) == "Bearer real"


# ---------------------------------------------------------------------------
# P-2 — outbound requests go to the address that was validated
# ---------------------------------------------------------------------------

def test_http_url_is_pinned_to_the_validated_address():
    url, headers = notifications._pin_outbound_url("http://ntfy.example.com/topic", "198.51.100.7")
    assert url == "http://198.51.100.7/topic"
    # The far end still routes on the name.
    assert headers == {"Host": "ntfy.example.com"}


def test_pinning_preserves_port_path_and_query():
    url, headers = notifications._pin_outbound_url(
        "http://ntfy.example.com:8080/topic?x=1", "198.51.100.7"
    )
    assert url == "http://198.51.100.7:8080/topic?x=1"
    assert headers == {"Host": "ntfy.example.com:8080"}


def test_ipv6_literals_are_bracketed():
    url, _ = notifications._pin_outbound_url("http://ntfy.example.com/t", "2001:db8::1")
    assert url == "http://[2001:db8::1]/t"


def test_https_urls_are_left_alone():
    """
    Certificate verification already defeats a rebind here, and rewriting the host is
    how you accidentally turn verification off. Deliberately untouched.
    """
    original = "https://push.example.com/UP?token=abc"
    url, headers = notifications._pin_outbound_url(original, "198.51.100.7")
    assert url == original
    assert headers == {}


def test_unresolved_address_leaves_the_url_unchanged():
    original = "http://ntfy.example.com/topic"
    assert notifications._pin_outbound_url(original, None) == (original, {})


def test_guard_returns_the_address_it_validated(monkeypatch):
    """
    The pinning is only worth anything if the guard hands back what it checked.

    A genuinely globally-routable address is required here: the RFC 5737 documentation
    ranges (198.51.100.0/24 and friends) are themselves non-global, so the guard rejects
    them — correctly, and it caught this test getting it wrong.
    """
    monkeypatch.setattr(
        outbound.socket, "getaddrinfo",
        lambda host, port, **kw: [(2, 1, 6, "", (_PUBLIC_IP, 0))],
    )
    assert notifications._assert_safe_outbound_url("http://ntfy.example.com/t") == _PUBLIC_IP


def test_guard_still_rejects_internal_addresses(monkeypatch):
    monkeypatch.setattr(
        outbound.socket, "getaddrinfo",
        lambda host, port, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ValueError):
        notifications._assert_safe_outbound_url("http://rebind.example.com/t")


def test_guard_rejects_when_any_answer_is_internal(monkeypatch):
    """
    A round-robin answer mixing a public and an internal address must not pass on the
    strength of the public one — requests may pick either.
    """
    monkeypatch.setattr(
        outbound.socket, "getaddrinfo",
        lambda host, port, **kw: [
            (2, 1, 6, "", (_PUBLIC_IP, 0)),   # public first, so the check cannot
            (2, 1, 6, "", ("10.0.0.5", 0)),   # pass by stopping at the first answer
        ],
    )
    with pytest.raises(ValueError):
        notifications._assert_safe_outbound_url("http://rebind.example.com/t")


# ---------------------------------------------------------------------------
# P-3 — a reset token with no deadline is expired, not eternal
# ---------------------------------------------------------------------------

def _user_with_expiry(expires_at):
    return types.SimpleNamespace(password_reset_token_expires_at=expires_at)


def test_missing_expiry_counts_as_expired():
    assert _reset_token_is_expired(_user_with_expiry(None)) is True


def test_past_expiry_is_expired():
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    assert _reset_token_is_expired(_user_with_expiry(past)) is True


def test_future_expiry_is_valid():
    future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    assert _reset_token_is_expired(_user_with_expiry(future)) is False


def test_naive_datetimes_are_read_as_utc():
    """SQLite hands back naive values; reading them as local time shifts the deadline."""
    naive_future = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(hours=6)
    naive_past = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(hours=6)
    assert _reset_token_is_expired(_user_with_expiry(naive_future)) is False
    assert _reset_token_is_expired(_user_with_expiry(naive_past)) is True


def test_malformed_port_does_not_raise_out_of_a_notification_send():
    """
    The SSRF guard only ever looks at the hostname, so a URL with an unusable port
    reaches the pinning step intact. Falling back to the original URL keeps that a
    requests-level failure instead of an exception thrown from the send path.
    """
    original = "http://ntfy.example.com:99999/topic"
    assert notifications._pin_outbound_url(original, _PUBLIC_IP) == (original, {})
