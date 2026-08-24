"""
Absolute URLs for links that leave the server.

`request.url_for()` builds its scheme and authority from the incoming request — which
means from the `Host` header, a value the client sends and the bundled nginx config
forwards verbatim (`proxy_set_header Host $host`). For a link that is rendered back
into the same response that is harmless. For a link that is *mailed* it is not: a
password reset requested with a forged `Host` produced a mail, addressed to the real
account owner, whose button pointed at the attacker's server and carried the reset
token in the path. One click and the account was gone, with no attacker-controlled
content visible in the message.

Links in mails are therefore built from `SERVER_BASE_URL`, the one place where the
operator states what this deployment is actually called. The path still comes from
the router, so a renamed route keeps its link.

TrustedHostMiddleware in app/main.py rejects unknown hosts as a second layer. Both
are needed: the middleware alone would be a configuration item that silently stops
protecting the moment someone widens it to `*`, and this function alone would leave
every other Host-derived value (redirects, `request.base_url`) unguarded.
"""
from urllib.parse import urlparse, urlunparse

from fastapi import Request

from app.config import settings


def external_url_for(request: Request, name: str, **path_params) -> str:
    """
    Build an absolute URL for route `name` using the configured public base URL.

    Falls back to whatever `request.url_for()` produced if SERVER_BASE_URL is unset or
    unparseable — an unusable link in a mail would be a worse failure mode than a
    Host-derived one, and the middleware still guards the request path itself.
    """
    routed = urlparse(str(request.url_for(name, **path_params)))

    base = urlparse(str(settings.SERVER_BASE_URL).rstrip('/'))
    if not base.scheme or not base.netloc:
        return urlunparse(routed)

    # Keep the base URL's path prefix if the deployment sits under a sub-path.
    path = f"{base.path.rstrip('/')}{routed.path}" if base.path.strip('/') else routed.path

    return urlunparse((base.scheme, base.netloc, path, routed.params, routed.query, routed.fragment))


def trusted_hosts() -> list[str]:
    """
    Host values this deployment answers to, for TrustedHostMiddleware.

    Derived from SERVER_BASE_URL so there is nothing extra to configure and nothing
    that can drift away from it. Loopback names are always included: health checks
    and the local `curl` of an operator arrive with `Host: localhost` and are not a
    path by which anything host-derived reaches a user.
    """
    # Starlette strips the port from the Host header before matching, so only bare
    # host names belong here — a "host:port" entry would never match, and a "host:*"
    # entry is rejected outright (its wildcard syntax is for subdomains, `*.example.com`).
    hosts: list[str] = ["localhost", "127.0.0.1", "[::1]"]

    parsed = urlparse(str(settings.SERVER_BASE_URL))
    if parsed.hostname:
        hosts.append(parsed.hostname)

    # Deduplicate, keeping order stable so the startup log is readable.
    seen: set[str] = set()
    return [h for h in hosts if not (h in seen or seen.add(h))]
