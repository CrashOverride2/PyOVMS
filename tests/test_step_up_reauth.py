"""
M-4 — step-up re-authentication for actions that change how an account is entered.

`verify_password` had three call sites in the entire repo: the login and the two
password changes. Everything else ran on the session alone — disabling TOTP,
registering a WebAuthn credential, deleting one, creating an API key, changing the
e-mail address, deleting the account.

The chain worth fixing: brief access to a logged-in session was enough to register a
passkey with `usage_mode='passwordless'`. That is a permanent second way in, it does
not depend on the password, and it survives a password change — the owner only
notices if they open the WebAuthn tab.

Implemented as one shared marker with a freshness window rather than a per-action
token, so a new sensitive route gets the rule by importing it. These tests pin both
halves: that the sensitive routes ask, and that ordinary actions still do not.
"""

import inspect
import time

import pytest

from app.routers.ui import profile as ui_profile
from app.routers.ui import webauthn as ui_webauthn
from app.utils import step_up


def _code_only(obj):
    lines = inspect.getsource(obj).splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


class _FakeRequest:
    def __init__(self):
        self.session = {}


# ---------------------------------------------------------------------------
# The freshness marker itself
# ---------------------------------------------------------------------------


def test_no_marker_means_no_recent_reauth():
    assert step_up.has_recent_reauth(_FakeRequest(), 1) is False


def test_marking_grants_a_window():
    request = _FakeRequest()
    step_up.mark_reauthenticated(request, 1)

    assert step_up.has_recent_reauth(request, 1) is True
    assert 0 < step_up.seconds_remaining(request, 1) <= step_up.STEP_UP_WINDOW_SECONDS


def test_marker_expires():
    request = _FakeRequest()
    step_up.mark_reauthenticated(request, 1)
    request.session["step_up_at"] = time.time() - (step_up.STEP_UP_WINDOW_SECONDS + 1)

    assert step_up.has_recent_reauth(request, 1) is False


def test_marker_is_bound_to_the_user():
    """
    A session that changes hands must not inherit the other account's freshness.
    """
    request = _FakeRequest()
    step_up.mark_reauthenticated(request, 1)

    assert step_up.has_recent_reauth(request, 2) is False


def test_future_timestamp_is_not_treated_as_valid_forever():
    """A tampered or clock-skewed value must fail closed, not grant an endless pass."""
    request = _FakeRequest()
    step_up.mark_reauthenticated(request, 1)
    request.session["step_up_at"] = time.time() + 10_000

    assert step_up.has_recent_reauth(request, 1) is False


def test_non_numeric_marker_is_rejected():
    request = _FakeRequest()
    request.session["step_up_user_id"] = 1
    request.session["step_up_at"] = "not-a-timestamp"

    assert step_up.has_recent_reauth(request, 1) is False


def test_clearing_revokes_the_window():
    request = _FakeRequest()
    step_up.mark_reauthenticated(request, 1)
    step_up.clear_reauthentication(request)

    assert step_up.has_recent_reauth(request, 1) is False


def test_window_is_short():
    assert 0 < step_up.STEP_UP_WINDOW_SECONDS <= 900


# ---------------------------------------------------------------------------
# Which routes are gated
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "route",
    [
        "ui_create_api_key_route",
        "ui_totp_disable_submit_route",
        # Enabling is the more dangerous direction and was missed by round 11: someone
        # holding a session briefly can enrol their own authenticator on an account
        # that had no 2FA, which bumps token_version (logging the owner out everywhere)
        # and leaves the owner unable to log in at all.
        "ui_totp_enable_submit_route",
        "ui_totp_setup_form_route",
        "ui_delete_profile_submit_route",
        "ui_update_profile_submit_route",
    ],
)
def test_sensitive_profile_routes_require_step_up(route):
    source = _code_only(getattr(ui_profile, route))

    assert "_needs_step_up(" in source, f"{route} is not gated"


def test_totp_enrolment_is_gated_before_the_secret_is_generated():
    """
    The gate on the setup page must come before the secret exists, so a refused
    confirmation leaves nothing half-built in the session.
    """
    source = _code_only(ui_profile.ui_totp_setup_form_route)

    assert source.index("_needs_step_up(") < source.index("generate_totp_secret()")


def test_totp_enable_is_gated_before_the_secret_is_stored():
    """
    /setup being gated is convenience; this is the load-bearing one. A caller can POST
    straight here with a secret left in the session from an earlier visit.
    """
    source = _code_only(ui_profile.ui_totp_enable_submit_route)

    assert source.index("_needs_step_up(") < source.index("enable_totp_for_user(")


def test_email_change_is_gated_but_the_rest_of_the_profile_is_not():
    """
    The e-mail address is where reset links go, so changing it is a takeover
    primitive. Name, timezone and units are not — gating those would train people to
    type their password for trivia, which is how step-up stops meaning anything.
    """
    source = _code_only(ui_profile.ui_update_profile_submit_route)

    gate = source.index("_needs_step_up(")
    email_branch = source.index("if email_to_update != current_user.email:")
    assert email_branch < gate, "the gate is not inside the e-mail-changed branch"

    for field in ("timezone", "unit_preference", "full_name"):
        field_assignment = source.index(f"update_payload_dict['{field}']")
        assert field_assignment > gate or "email" in source[gate:field_assignment], (
            f"changing {field} appears to be gated"
        )


@pytest.mark.parametrize(
    "route", ["ui_webauthn_register_begin", "ui_webauthn_delete"]
)
def test_webauthn_credential_changes_require_step_up(route):
    source = _code_only(getattr(ui_webauthn, route))

    assert "has_recent_reauth(" in source, f"{route} is not gated"


def test_webauthn_registration_is_gated_before_a_challenge_is_issued():
    """Failing after the challenge would leave a usable half-finished flow."""
    source = _code_only(ui_webauthn.ui_webauthn_register_begin)

    gate = source.index("has_recent_reauth(")
    challenge = source.index("generate_registration_options")
    assert gate < challenge


# ---------------------------------------------------------------------------
# How freshness is obtained
# ---------------------------------------------------------------------------


def test_login_marks_the_session_as_freshly_authenticated():
    """Otherwise every user would be asked for their password twice in a row."""
    from app.routers.ui import auth as ui_auth

    source = _code_only(ui_auth)

    assert "mark_reauthenticated(" in source


@pytest.mark.parametrize(
    "module_path,route",
    [
        ("app.routers.ui.auth", "ui_login_submit_route"),
        ("app.routers.ui.auth", "ui_login_totp_submit_route"),
        ("app.routers.ui.webauthn", "ui_webauthn_auth_complete"),
        ("app.routers.ui.webauthn", "ui_webauthn_2fa_complete"),
    ],
)
def test_every_login_completion_marks_freshness(module_path, route):
    """
    A blanket check over the four routes that can finish a login, not a list of the
    ones somebody remembered.

    ui_webauthn_2fa_complete was the one that did not, and it is the only login an
    account using a security key as its second factor can perform. Everything gated
    behind step-up — creating an API key above all — was therefore unreachable for
    those accounts. That is not a theoretical gap: /api/v1/auth/device-token refuses
    them on purpose, so the mobile app falls back to the web flow and ends on the
    confirm-password page instead of a key. Found by replaying the app's requests
    against a live server, not by reading the code.
    """
    import importlib

    module = importlib.import_module(module_path)
    source = _code_only(getattr(module, route))

    assert "mark_reauthenticated(" in source, f"{route} completes a login without marking freshness"


def test_password_change_marks_the_session():
    source = _code_only(ui_profile.ui_change_password_submit_route)

    assert "mark_reauthenticated(" in source


def test_passwordless_login_marks_the_session():
    """
    A passkey login with user verification proves possession plus PIN/biometrics,
    which is at least as strong as the password it replaces.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)

    assert "mark_reauthenticated(" in source


def test_confirm_password_route_verifies_the_password():
    source = _code_only(ui_profile.ui_confirm_password_submit_route)

    assert "security.verify_password(" in source
    assert "mark_reauthenticated(" in source
    verify = source.index("security.verify_password(")
    mark = source.index("mark_reauthenticated(")
    assert verify < mark, "the session is marked before the password is checked"


def test_confirm_password_failures_are_rate_limited():
    """
    An attacker on a stolen session guessing the password here is doing exactly what
    the login rate limiter exists for.
    """
    source = _code_only(ui_profile.ui_confirm_password_submit_route)

    assert "record_failure(" in source
    assert "is_blocked(" in source


def test_confirm_password_verifies_csrf():
    source = _code_only(ui_profile.ui_confirm_password_submit_route)

    assert "verify_csrf_token(" in source


# ---------------------------------------------------------------------------
# The redirect target cannot leave the application
# ---------------------------------------------------------------------------


class _UrlRequest:
    """Minimal stand-in exposing base_url and url_for."""

    def __init__(self, base="http://testserver"):
        self.base_url = base + "/"

    def url_for(self, name, **kwargs):
        return "http://testserver/profile"


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example/steal",
        "//evil.example/steal",
        "http://evil.example",
        "javascript:alert(1)",
    ],
)
def test_next_url_cannot_leave_the_site(hostile):
    """
    The target is a query parameter, and the user lands on it right after proving
    their password — the moment they are least likely to check the address bar.
    """
    resolved = ui_profile._safe_next_url(_UrlRequest(), hostile)

    assert "evil.example" not in resolved
    assert not resolved.startswith("javascript:")


@pytest.mark.parametrize(
    "allowed",
    ["/profile?tab=2fa", "http://testserver/profile?tab=apikeys"],
)
def test_next_url_allows_local_targets(allowed):
    assert ui_profile._safe_next_url(_UrlRequest(), allowed) == allowed


def test_empty_next_url_falls_back_to_the_profile():
    assert ui_profile._safe_next_url(_UrlRequest(), "") == "http://testserver/profile"
