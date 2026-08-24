"""Outbound HTTP for the notification channels.

Three concerns live here, all of which used to sit at the top of the monolithic
notifications module:

* the SSRF guard (`assert_safe_outbound_url`) — every URL in this subsystem is
  user-supplied (per-vehicle NTFY server, UnifiedPush endpoint), so nothing may be
  requested before it has been resolved and inspected;
* DNS-rebind pinning (`pin_outbound_url`) — connect to the address that was actually
  vetted rather than resolving the name a second time;
* the HTTP client itself (`post`) — pooled per thread, redirect-free, with a bounded
  read of the response body.

URLs here carry credentials (NTFY's query-auth token, userinfo), so anything written
to a log goes through `redact_url()` first.

Nothing in here touches the database or the Jinja environment, which is what makes it
safe to import from `app.services.disposable_email_service` without dragging the whole
notification stack (firebase_admin, smtplib, the template loader) along.
"""

import ipaddress
import logging
import socket
import threading
import time
from http.cookiejar import DefaultCookiePolicy
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter

from app.notifications.errors import OutboundBlockedError

logger = logging.getLogger(__name__)

# (connect, read). Splitting the two means a tarpit that accepts the TCP connection and
# then says nothing is capped by the read timeout, while an unreachable host fails fast
# instead of burning the full budget on the handshake.
DEFAULT_TIMEOUT: Tuple[float, float] = (5.0, 10.0)

# How much of a response body is read for logging. A push endpoint is a third-party
# host we do not control; without a ceiling its error page is buffered into memory in
# full, on every retry, for every recipient.
MAX_RESPONSE_SNIPPET_BYTES = 2048

# Small on purpose: this pool exists to save the TCP+TLS handshake between repeated
# sends to the same push host, not to permit unbounded concurrency.
_POOL_CONNECTIONS = 4
_POOL_MAXSIZE = 8

# How long a resolution verdict is reused.
#
# Every send used to call getaddrinfo(), which is a blocking syscall with no timeout
# parameter — there is no way to bound it from Python. A resolver that has become slow
# therefore added its full latency to every notification, to every recipient, and to
# every retry, all while holding a worker from a small shared pool. One vehicle's ntfy
# hostname was enough to slow down the whole server.
#
# Caching narrows rather than widens the SSRF window: a rebinding attacker wants the
# second lookup to differ from the vetted one, and reusing the first verdict is exactly
# what denies that. The cost is that a legitimately re-pointed DNS record takes up to
# the positive TTL to be honoured, which for a push endpoint is not a real constraint.
# Failures are cached far more briefly — long enough to stop a dead resolver being
# re-consulted for every message in a burst, short enough that a host coming back is
# noticed promptly.
_DNS_CACHE_TTL_SECONDS = 60.0
_DNS_NEGATIVE_TTL_SECONDS = 10.0
_DNS_CACHE_MAX_ENTRIES = 2048

# hostname -> (expiry, validated_ip, error_message or None)
_dns_cache: dict = {}
_dns_cache_lock = threading.Lock()


def clear_dns_cache() -> None:
    """Drop the memoised resolution verdicts (tests, and after a network change)."""
    with _dns_cache_lock:
        _dns_cache.clear()


def _resolve_and_validate(hostname: str) -> Optional[str]:
    """Resolve `hostname` and reject it if any address is non-global. Cached.

    Returns the first validated address, or None when nothing parseable came back.
    """
    now = time.monotonic()
    with _dns_cache_lock:
        cached = _dns_cache.get(hostname)
        if cached is not None and cached[0] > now:
            _expiry, validated_ip, error = cached
            if error is not None:
                raise OutboundBlockedError(error)
            return validated_ip

    try:
        # SOCK_STREAM: without it getaddrinfo returns the same address once per socket
        # type, so every address is inspected three times for nothing.
        resolved_addrs = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        _remember_dns(hostname, None, f"Could not resolve hostname '{hostname}': {e}")
        raise OutboundBlockedError(f"Could not resolve hostname '{hostname}': {e}")

    validated: Optional[str] = None
    for _family, _type, _proto, _canonname, sockaddr in resolved_addrs:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not addr.is_global or addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
            message = (
                f"Outbound request to '{hostname}' resolves to non-global address {ip_str}. "
                "SSRF protection: request blocked."
            )
            _remember_dns(hostname, None, message)
            raise OutboundBlockedError(message)
        if validated is None:
            validated = ip_str

    _remember_dns(hostname, validated, None)
    return validated


def _remember_dns(hostname: str, validated_ip: Optional[str], error: Optional[str]) -> None:
    ttl = _DNS_NEGATIVE_TTL_SECONDS if error is not None else _DNS_CACHE_TTL_SECONDS
    with _dns_cache_lock:
        # Hostnames come from user-supplied URLs, so the key space is not ours to trust.
        # Clearing wholesale beats evicting one by one: the worst case is a burst of
        # fresh lookups, which is what the un-cached path did on every single send.
        if len(_dns_cache) >= _DNS_CACHE_MAX_ENTRIES:
            _dns_cache.clear()
        _dns_cache[hostname] = (time.monotonic() + ttl, validated_ip, error)


def assert_safe_outbound_url(url: str, allowed_schemes: tuple = ("http", "https")) -> Optional[str]:
    """
    Validate that a user-supplied URL does not target private/internal infrastructure.
    Resolves the hostname and rejects any non-global address to prevent SSRF.
    Raises ValueError if the URL is unsafe.

    The scheme allowlist is part of the check: without it the IP inspection below can be
    sidestepped entirely with file://, gopher:// or ftp:// URLs, which never reach
    getaddrinfo in a meaningful way but are still honoured by some clients. It is checked
    per URL, outside the resolution cache, because it is a property of the URL and not of
    the host.

    Returns the first validated address, so the caller can connect to *that* rather than
    resolve the name a second time — see pin_outbound_url(). None when nothing parseable
    came back, which leaves the caller with the un-pinned URL and the check still applied.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in allowed_schemes:
            raise OutboundBlockedError(
                f"Outbound URL scheme '{parsed.scheme}' is not allowed "
                f"(permitted: {', '.join(allowed_schemes)})."
            )
        hostname = parsed.hostname
        if not hostname:
            raise OutboundBlockedError(f"URL has no resolvable hostname: {url}")
        return _resolve_and_validate(hostname)
    except ValueError:
        raise
    except Exception as e:
        raise OutboundBlockedError(f"SSRF URL validation failed for '{url}': {e}")


def pin_outbound_url(url: str, ip: Optional[str]) -> tuple[str, dict]:
    """
    Rewrite a plain-HTTP URL to connect to `ip`, carrying the original name as Host.

    Returns (url_to_request, extra_headers).

    assert_safe_outbound_url() resolves the hostname and rejects internal addresses, but
    requests then resolves it again when it opens the connection. Someone who controls the
    DNS for a hostname they own can answer the first query with a public address and the
    second with 127.0.0.1: the check passes and the request still lands inside. Connecting
    to the address that was actually vetted closes that window.

    Only http:// is rewritten. On https:// a rebind is already stopped one layer down —
    reaching an internal service would need it to present a certificate valid for the
    attacker's own hostname, which it cannot, so the handshake fails before any request
    body is sent. Rewriting those too would mean handing urllib3 an IP as the connection
    target and re-supplying the hostname for SNI and verification, which silently disables
    certificate checking if it is got slightly wrong — a poor trade against a hole TLS
    already covers. This is also why the UnifiedPush endpoint is validated https-only.
    """
    if not ip:
        return url, {}
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "http":
            return url, {}

        # Host carries the name (with port), which is what the far end routes on.
        userinfo, _, hostport = parsed.netloc.rpartition("@")
        literal = f"[{ip}]" if ":" in ip else ip
        # .port raises on a malformed or out-of-range port, which the SSRF guard above
        # never looks at — it only needs the hostname.
        port = parsed.port
        netloc = literal if port is None else f"{literal}:{port}"
        if userinfo:
            netloc = f"{userinfo}@{netloc}"
        return urlunparse(parsed._replace(netloc=netloc)), {"Host": hostport}
    except ValueError:
        # Hand back the original URL rather than raising out of a notification send.
        # The SSRF check has already passed, so this is the behaviour that existed
        # before pinning: requests gets the URL and rejects it on its own terms.
        return url, {}


def redact_url(url: str) -> str:
    """Strip credentials from a URL before it reaches a log.

    NTFY's `query` auth mode puts the vehicle owner's access token in the query string,
    and a URL may carry userinfo; both would otherwise be written verbatim by the
    diagnostics below, where they outlive the request by however long logs are kept.
    """
    try:
        parsed = urlparse(url)
        if not parsed.query and "@" not in parsed.netloc:
            return url
        netloc = parsed.netloc.rpartition("@")[2]
        return urlunparse(parsed._replace(netloc=netloc, query="[redacted]" if parsed.query else ""))
    except ValueError:
        return "<unparseable url>"


class _BlockAllCookies(DefaultCookiePolicy):
    """Refuse to store or replay cookies.

    A pooled Session keeps a cookie jar. Push endpoints are third-party hosts, several
    of which may share one jar here; there is no reason for this subsystem to carry
    state between sends, and a jar that only ever grows is one more thing to bound.
    """

    def set_ok(self, cookie, request) -> bool:  # noqa: D102 - cookiejar protocol
        return False

    def return_ok(self, cookie, request) -> bool:  # noqa: D102 - cookiejar protocol
        return False


_thread_local = threading.local()

# Every live session, so that shutdown can close the sockets belonging to threads it
# cannot reach into. Without it the pooled connections are only released when the
# process exits, which is invisible in production but leaks a handful of file
# descriptors per reload in anything that restarts the app in-process.
_sessions: list = []
_sessions_lock = threading.Lock()


def get_session() -> requests.Session:
    """A connection-pooling Session, one per thread.

    Every send used to be a bare `requests.post`, i.e. a fresh TCP connection and TLS
    handshake per notification per recipient. A Session reuses them. It is kept
    thread-local rather than global because requests.Session is not documented as
    thread-safe, and the fan-out below deliberately runs sends in parallel; the number
    of threads doing this is bounded by the dispatch pool, so the number of sessions is
    too.
    """
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.cookies.set_policy(_BlockAllCookies())
        adapter = HTTPAdapter(
            pool_connections=_POOL_CONNECTIONS,
            pool_maxsize=_POOL_MAXSIZE,
            max_retries=0,  # retries are the caller's decision - see retry.py
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _thread_local.session = session
        with _sessions_lock:
            _sessions.append(session)
    return session


def close_all_sessions() -> None:
    """Close every pooled session.

    Call this only once the senders have stopped — it closes sessions owned by other
    threads, which is safe when nothing is using them any more and a use-after-close
    when something still is. `shutdown_dispatch_pool()` waits for its workers first,
    which is what makes it the right caller.
    """
    with _sessions_lock:
        sessions, _sessions[:] = list(_sessions), []
    for session in sessions:
        try:
            session.close()
        except Exception:  # pragma: no cover - closing must never raise on the way out
            logger.debug("Failed to close a pooled outbound session.", exc_info=True)
    _thread_local.session = None


def post(
    url: str,
    *,
    headers: Optional[dict] = None,
    data=None,
    json=None,
    timeout=DEFAULT_TIMEOUT,
    allowed_schemes: tuple = ("http", "https"),
) -> Tuple[int, str]:
    """SSRF-checked, address-pinned, redirect-free POST.

    Returns (status_code, body_snippet). Raises ValueError when the guard refuses the
    URL; transport exceptions propagate so the retry decorator can classify them.

    allow_redirects is off deliberately: a 302 is resolved by requests itself, which
    means a fresh DNS lookup to a host nobody vetted — it would hand back exactly the
    SSRF the guard above just closed.
    """
    validated_ip = assert_safe_outbound_url(url, allowed_schemes=allowed_schemes)
    request_url, pin_headers = pin_outbound_url(url, validated_ip)
    merged_headers = {**(headers or {}), **pin_headers}

    response = get_session().post(
        request_url,
        headers=merged_headers or None,
        data=data,
        json=json,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    try:
        raw = response.raw.read(MAX_RESPONSE_SNIPPET_BYTES + 1, decode_content=True) or b""
        if len(raw) > MAX_RESPONSE_SNIPPET_BYTES:
            raw = raw[:MAX_RESPONSE_SNIPPET_BYTES]
            logger.debug("Outbound response from %s truncated for logging.", redact_url(request_url))
        snippet = raw.decode("utf-8", "replace")
    except Exception:
        snippet = ""
    finally:
        response.close()

    return response.status_code, snippet


# Backwards-compatible aliases. The underscore-prefixed names were the public surface
# of the old module and are still referenced from the test suite.
_assert_safe_outbound_url = assert_safe_outbound_url
_pin_outbound_url = pin_outbound_url
