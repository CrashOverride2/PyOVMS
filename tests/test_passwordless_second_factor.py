"""
M-5 — a passkey replaces the password, not the second factor.

`/webauthn/auth/complete` minted a fully authenticated session the moment an assertion
verified: it set `is_2fa_completed=True` unconditionally. An account with a passkey
*and* TOTP enabled was therefore reachable with the passkey alone.

This is the same hole as N-6, one path over. Round 6 moved the ranking into
app.utils.two_factor precisely so no login path could disagree about what an account
requires, and wired up the UI login, the TOTP submit and the device-token endpoint.
The passwordless WebAuthn path was never connected, and nothing failed when it drifted
— which is what these tests exist to prevent.

The second half covers user verification. Asking for REQUIRED in the options is only a
request; the flag in the returned authenticator data is the fact. The library defaults
to not checking it, so a presence-only touch — possession of the key, no PIN, no
biometrics — produced a full session. For a flow that *is* the whole login, that is
single-factor authentication under another name.
"""

import inspect

import pytest

from app.routers.ui import webauthn as ui_webauthn
from app.utils import webauthn_helper as helper_module
from app.utils.two_factor import SecondFactor


def _code_only(obj):
    """
    Source with comment lines removed.

    Tests that reason about the *order* of two statements have to, or they match the
    comment explaining the bug instead of the code causing it — which is exactly what
    happened while writing these.
    """
    lines = inspect.getsource(obj).splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


# ---------------------------------------------------------------------------
# The bypass
# ---------------------------------------------------------------------------


def test_passwordless_login_consults_the_shared_ranking():
    """
    It must ask app.utils.two_factor rather than deciding locally. A second copy of
    the rule is how the TOTP route and the login handler drifted apart in the first
    place.
    """
    source = inspect.getsource(ui_webauthn.ui_webauthn_auth_complete)

    assert "required_second_factor(" in source, (
        "the passwordless login does not consult required_second_factor()"
    )


def test_passwordless_login_does_not_unconditionally_complete_2fa():
    """
    The precise defect: `is_2fa_completed=True` reached before any check of what the
    account requires.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)

    ranking = source.index("required_second_factor(")
    completion = source.index("is_2fa_completed=True")

    assert ranking < completion, (
        "the session is marked 2FA-complete before the account's requirement is known"
    )


def test_passwordless_login_hands_off_to_the_required_factor():
    """
    A pending login, not a finished one: the handler must park the user id for the
    second-factor step and send the client onward instead of setting the cookie.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)
    handoff = source[source.index("required_second_factor("):]

    assert "pending_2fa_user_id" in handoff
    assert "ui_login_totp_form" in handoff
    assert "ui_webauthn_2fa_form" in handoff


def test_handoff_returns_before_issuing_a_token():
    """
    The branch has to *return*. Falling through would set the access-token cookie
    anyway and make the redirect cosmetic — a bypass that still looks fixed.
    """
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)

    branch = source[source.index("if required != SecondFactor.NONE:"):]
    branch_end = branch.index("crud.user.record_login")

    assert "return JSONResponse" in branch[:branch_end]
    assert "set_cookie" not in branch[:branch_end], (
        "the second-factor branch issues a session cookie"
    )
    assert "create_access_token" not in branch[:branch_end]


@pytest.mark.parametrize(
    "factor,expected_route",
    [
        (SecondFactor.TOTP, "ui_login_totp_form"),
        (SecondFactor.WEBAUTHN, "ui_webauthn_2fa_form"),
    ],
)
def test_each_required_factor_has_a_destination(factor, expected_route):
    """Neither branch may silently fall through to a completed session."""
    source = inspect.getsource(ui_webauthn.ui_webauthn_auth_complete)

    assert expected_route in source, f"no destination for {factor.value}"


def test_no_second_copy_of_the_ranking_rule():
    """
    The N-6 lesson. This module must not re-derive which factor applies; that is what
    app.utils.two_factor is for.
    """
    source = inspect.getsource(ui_webauthn)
    complete = _code_only(ui_webauthn.ui_webauthn_auth_complete)

    assert "is_totp_enabled" not in complete, (
        "the passwordless handler inspects is_totp_enabled directly instead of "
        "asking required_second_factor()"
    )
    assert source.count("required_second_factor(") >= 1


# ---------------------------------------------------------------------------
# User verification
# ---------------------------------------------------------------------------


def test_passwordless_verification_demands_user_verification():
    """Possession alone must not be a full login."""
    source = _code_only(ui_webauthn.ui_webauthn_auth_complete)
    verify_call = source[source.index("verify_authentication_response("):]

    assert "require_user_verification=True" in verify_call[:400]


def test_passwordless_options_request_user_verification():
    source = _code_only(ui_webauthn.ui_webauthn_auth_begin)

    assert "require_user_verification=True" in source


def test_verification_flag_is_passed_through_to_the_library():
    """
    The helper must forward it. Accepting the argument and dropping it would leave
    the library on its default of False — the request stays advisory and nothing
    checks the flag that actually matters.
    """
    source = inspect.getsource(helper_module.WebAuthnHelper.verify_authentication_response)

    assert "require_user_verification=require_user_verification" in source


def test_passwordless_registration_requires_a_uv_capable_authenticator():
    """
    Registration and login must agree. Registering a passwordless credential with
    PREFERRED could produce a UV-incapable key that the login then rejects — handing
    the user a passkey that fails at sign-in.

    The UV requirement must be derived from the *normalised* role, not from the raw
    request field: the value is pinned into the session here and read back at /complete,
    so an unrecognised usage_mode cannot end up as a passwordless credential that was
    never asked to prove it can do UV.
    """
    source = _code_only(ui_webauthn.ui_webauthn_register_begin)

    assert "usage_mode = data.usage_mode if data.usage_mode in ('passwordless', '2fa')" in source
    assert "require_user_verification=(usage_mode == 'passwordless')" in source
    assert "request.session['webauthn_register_usage_mode'] = usage_mode" in source


def test_registration_role_is_taken_from_the_session_not_the_request():
    """
    Beginning as '2fa' (user_verification PREFERRED) and completing as 'passwordless'
    stored a credential in the stronger role without the UV capability its login
    demands. The role decided at /begin is the one that gets persisted.
    """
    source = _code_only(ui_webauthn.ui_webauthn_register_complete)

    assert "stored_usage_mode = request.session.get('webauthn_register_usage_mode')" in source
    assert "usage_mode=stored_usage_mode" in source
    assert "if data.usage_mode != stored_usage_mode:" in source


def test_second_factor_flow_still_accepts_presence_only():
    """
    Deliberate asymmetry: in the 2FA flow the password has already been checked and
    proving possession is exactly the job. Demanding a PIN there would be a UX
    regression with no security gain, so this pins the intent.
    """
    begin_2fa = _code_only(ui_webauthn.ui_webauthn_2fa_begin)
    complete_2fa = _code_only(ui_webauthn.ui_webauthn_2fa_complete)

    assert "require_user_verification=True" not in begin_2fa
    assert "require_user_verification=True" not in complete_2fa


def test_helper_defaults_to_not_requiring_verification():
    """
    The default must stay permissive so the 2FA path is unaffected; the passwordless
    path opts in explicitly.
    """
    for fn in (
        helper_module.WebAuthnHelper.generate_authentication_options,
        helper_module.WebAuthnHelper.verify_authentication_response,
        helper_module.WebAuthnHelper.generate_registration_options,
    ):
        signature = inspect.signature(fn)
        assert signature.parameters["require_user_verification"].default is False
