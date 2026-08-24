"""
The CSRF token must survive an open page, and a failure must not look like a crash.

Both properties were learned from the same report: a form left open long enough came back
with "Invalid or expired CSRF token", rendered as a page of raw JSON text.

* The token *is* refreshed without a reload — base.html polls `/csrf-token/refresh` — but
  the poll re-armed itself only on success, guessed its interval from
  ACCESS_TOKEN_EXPIRE_MINUTES (unrelated to the token's lifetime), renewed only *after*
  the hard expiry, and could not reach a token held in JS rather than in a hidden input.
* Every uncaught CSRF rejection reached the browser as `{"detail": ...}`, because the
  only handler for HTTPException serialised JSON regardless of who was asking.

The API and the fetch() callers in the templates still depend on that JSON body, so the
HTML page is for navigations only.
"""

import pathlib
import re
import sys

from starlette.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.csrf_protection import (  # noqa: E402
    CSRF_TOKEN_EXPIRATION,
    CSRF_TOKEN_RENEW_AFTER,
    csrf_token_needs_renewal,
    generate_csrf_token,
)
from app.main import app  # noqa: E402

TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / "app" / "templates"

NAVIGATION = {"sec-fetch-mode": "navigate", "accept": "text/html"}
FETCH = {"sec-fetch-mode": "same-origin", "accept": "*/*"}


def _client() -> TestClient:
    # https, because the session cookie is issued with `secure` under FORCE_SECURE_COOKIES
    # and would not be sent back over http — the poll would then look like a lapsed session.
    return TestClient(app, base_url="https://testserver")


def _with_session() -> TestClient:
    client = _client()
    # The login form is the page most likely to sit open long enough to need the refresh,
    # and it establishes the session the refresh endpoint requires.
    assert client.get("/login", headers=NAVIGATION).status_code == 200
    return client


def test_renewal_happens_before_the_hard_expiry():
    """A token is replaced at half life, not once it is already rejected.

    Renewing only at CSRF_TOKEN_EXPIRATION leaves every open form holding a dead token
    for as long as the gap to the next poll.
    """
    assert CSRF_TOKEN_RENEW_AFTER < CSRF_TOKEN_EXPIRATION

    token = generate_csrf_token()
    assert csrf_token_needs_renewal(token) is False
    assert csrf_token_needs_renewal(token, renew_after=-1) is True
    assert csrf_token_needs_renewal("not-a-token") is True


def test_refresh_endpoint_is_stable_and_states_its_cadence():
    client = _with_session()

    first = client.get("/csrf-token/refresh")
    assert first.status_code == 200
    payload = first.json()
    assert payload["csrf_token"]

    # The client must not have to guess. The interval has to stay inside the session
    # cookie's max_age, because this poll is also what keeps that sliding cookie alive.
    from app.config import settings

    assert 60 <= payload["next_refresh_in"] <= settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # A still-fresh token comes back unchanged. Rotating on every poll would invalidate
    # the token a second tab had already rendered.
    assert client.get("/csrf-token/refresh").json()["csrf_token"] == payload["csrf_token"]


def test_refresh_does_not_mint_a_session_for_an_anonymous_caller():
    response = _client().get("/csrf-token/refresh")
    assert response.status_code == 403
    assert not response.cookies


def test_csrf_failure_renders_a_page_for_a_navigation_and_json_for_fetch():
    client = _with_session()

    # /profile/webauthn/auth/begin verifies the token without catching the rejection,
    # so it is the shortest path to an uncaught CSRF failure.
    page = client.post(
        "/profile/webauthn/auth/begin", json={"csrf_token": "garbage"}, headers=NAVIGATION
    )
    assert page.status_code == 403
    assert page.headers["content-type"].startswith("text/html")
    assert "<html" in page.text.lower()
    # The explanation, not the raw `detail` string.
    assert "no longer valid" in page.text

    data = client.post(
        "/profile/webauthn/auth/begin", json={"csrf_token": "garbage"}, headers=FETCH
    )
    assert data.status_code == 403
    assert data.headers["content-type"].startswith("application/json")
    assert "CSRF" in data.json()["detail"]


def test_api_paths_never_get_html_even_from_a_browser():
    response = _client().get("/api/v1/vehicles", headers=NAVIGATION)
    assert response.status_code in (401, 403)
    assert response.headers["content-type"].startswith("application/json")


def test_unknown_page_is_a_rendered_404_for_a_navigation():
    response = _client().get("/no-such-page", headers=NAVIGATION)
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")


def test_redirects_raised_as_http_exceptions_still_redirect():
    """The auth dependencies raise HTTPException(307, Location=...).

    Turning *every* HTTPException into a page would break every guarded route.
    """
    response = _client().get("/dashboard", headers=NAVIGATION, follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers.get("location")


def test_refresh_poll_rearms_itself_after_a_failure():
    """One network blip must not stop the refresh for the life of the page.

    The chain used to be re-armed inside `if (r.ok)` only, which is the difference
    between "recovers when the tab comes back" and "silently dead until reload".
    """
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert ".catch(" in base
    # Rescheduling has to happen on the failure path too, not just the success path.
    catch_body = base.split(".catch(", 1)[1].split(".finally(", 1)[0]
    assert "schedule(" in catch_body, "the refresh poll does not re-arm after a failure"

    # setTimeout does not fire in a frozen tab or across a sleeping machine, so returning
    # to the page has to be its own trigger.
    assert "visibilitychange" in base
    assert "pageshow" in base


def test_js_held_tokens_read_the_refreshed_value():
    """A token baked into JS at render time cannot be patched by the poll.

    Hidden inputs are updated in place; these read `window.csrfToken` instead, so the
    WebAuthn ceremonies, the TOTP rotation page and the vehicle terminal track the
    refresh too.
    """
    assert "window.csrfToken =" in (TEMPLATES / "base.html").read_text(encoding="utf-8")

    for name in (
        "webauthn_login.html",
        "webauthn_register.html",
        "login_webauthn_2fa.html",
        "totp_key_rotation.html",
        "vehicle_detail.html",
    ):
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        assert "window.csrfToken" in source, f"{name} does not follow the refreshed token"
        # A *bare* literal is what the poll cannot reach. Keeping one as the fallback
        # behind `window.csrfToken ||` is fine — that is the render-time value, used
        # only if base.html never defined the live one.
        baked = re.findall(r"csrf_token'?\s*[:,]\s*'\{\{ csrf_token \}\}'", source)
        assert not baked, f"{name} still submits a token baked in at render time: {baked}"
