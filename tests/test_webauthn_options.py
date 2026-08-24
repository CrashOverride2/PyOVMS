"""
The WebAuthn option builders must actually run against the installed library.

Every other test around WebAuthn checks *our* logic — which factor an account needs,
which usage mode a credential was registered in. None of them ever called
generate_registration_options() or generate_authentication_options(), so nothing in the
suite touched the `webauthn` package's own API surface.

That gap had teeth. Upgrading webauthn 2.7.1 -> 3.0.0 turned a plain string into a hard
error: AuthenticatorSelectionCriteria(resident_key="discouraged") makes options_to_json()
raise AttributeError, because 3.0 calls .value on the field and expects the enum. The
suite stayed green through the upgrade; the break only showed up when the option builders
were called by hand. (The string lived in app/webauthn_support.py, a duplicate module that
nothing imported and which has since been deleted — the live helper always used the enums.)

These tests are the missing coverage: build both option sets exactly as the router does
and serialise them. Any future release that changes what the library accepts fails here
instead of at a user's security key.
"""

import json
import types

import pytest

from app.utils.webauthn_helper import WebAuthnHelper


@pytest.fixture
def helper() -> WebAuthnHelper:
    """Configured the same way app/routers/ui/webauthn.py configures the real one."""
    return WebAuthnHelper(
        rp_id="localhost",
        rp_name="PyOVMS",
        origin="http://localhost:8000",
    )


@pytest.fixture
def user():
    """Stand-in for models_db.User — the builder only reads these three attributes."""
    return types.SimpleNamespace(id=1, username="testuser", full_name="Test User")


@pytest.mark.parametrize("require_uv", [False, True])
def test_registration_options_build_and_serialise(helper, user, require_uv):
    """
    Covers both call sites: the 2FA flow passes require_user_verification=False, the
    passwordless flow True. The returned dict must survive json.dumps — the router hands
    it straight to JSONResponse, so a value the serialiser chokes on is a 500 at
    registration time.
    """
    options = helper.generate_registration_options(
        user=user,
        existing_credentials=[],
        require_user_verification=require_uv,
    )

    json.dumps(options)  # must not raise

    public_key = options["publicKey"]
    assert public_key["challenge"]
    assert public_key["rp"]["id"] == "localhost"

    expected_uv = "required" if require_uv else "preferred"
    assert public_key["authenticatorSelection"]["userVerification"] == expected_uv


def test_registration_user_verification_matches_the_login_it_registers_for(helper, user):
    """
    A passwordless credential must be registered as UV REQUIRED, because the passwordless
    login rejects assertions whose UV flag is unset. Registering it as PREFERRED hands the
    user a key that silently fails at sign-in.
    """
    passwordless = helper.generate_registration_options(
        user=user, existing_credentials=[], require_user_verification=True
    )
    second_factor = helper.generate_registration_options(
        user=user, existing_credentials=[], require_user_verification=False
    )

    assert passwordless["publicKey"]["authenticatorSelection"]["userVerification"] == "required"
    assert second_factor["publicKey"]["authenticatorSelection"]["userVerification"] == "preferred"


def test_passwordless_registration_demands_a_resident_key(helper, user):
    """
    A passwordless credential has to be discoverable, or the login cannot find it
    without naming it — and naming it means naming every other one too, since the
    passwordless login has not identified a user yet.

    2FA credentials are looked up by user id after the password step, so they get
    DISCOURAGED: demanding a resident key there would consume one of the handful of
    slots a hardware key has for no benefit.
    """
    passwordless = helper.generate_registration_options(
        user=user, existing_credentials=[], require_discoverable=True
    )
    second_factor = helper.generate_registration_options(
        user=user, existing_credentials=[], require_discoverable=False
    )

    assert passwordless["publicKey"]["authenticatorSelection"]["residentKey"] == "required"
    assert second_factor["publicKey"]["authenticatorSelection"]["residentKey"] == "discouraged"


def test_passwordless_registration_asks_for_credprops(helper, user):
    """
    residentKey=required is a request, not a guarantee. credProps.rk is how the server
    learns what it actually got, and a credential it cannot confirm stays in the list
    the login names — so losing this extension silently reintroduces the disclosure for
    every newly registered key.
    """
    passwordless = helper.generate_registration_options(
        user=user, existing_credentials=[], require_discoverable=True
    )
    second_factor = helper.generate_registration_options(
        user=user, existing_credentials=[], require_discoverable=False
    )

    assert passwordless["publicKey"]["extensions"]["credProps"] is True
    assert "extensions" not in second_factor["publicKey"], (
        "credProps was requested for a credential whose discoverability is never used"
    )


def test_no_credentials_discloses_no_credential_ids(helper):
    """
    Once every passwordless credential is discoverable, the login passes an empty list
    and the response must carry no credential id at all.

    The library serialises that as `allowCredentials: []` rather than omitting the key,
    which is the correct discoverable-credential request: WebAuthn L2 defines a
    discoverable credential as one usable "in authentication ceremonies where the
    Relying Party does not provide any credential IDs, i.e. the Relying Party invokes
    navigator.credentials.get() with an empty allowCredentials argument". Empty and
    absent mean the same thing here, so the assertion is about the ids, not the key.
    """
    options = helper.generate_authentication_options(
        user_credentials=[], require_user_verification=True
    )

    assert not options["publicKey"].get("allowCredentials"), (
        "an empty credential list still produced allowCredentials entries"
    )


@pytest.mark.parametrize("require_uv", [False, True])
def test_authentication_options_build_and_serialise(helper, require_uv):
    options = helper.generate_authentication_options(
        user_credentials=[],
        require_user_verification=require_uv,
    )

    json.dumps(options)  # must not raise

    public_key = options["publicKey"]
    assert public_key["challenge"]
    assert public_key["userVerification"] == ("required" if require_uv else "preferred")


def test_challenges_are_not_reused(helper, user):
    """A fixed challenge would make every assertion replayable."""
    first = helper.generate_registration_options(user=user, existing_credentials=[])
    second = helper.generate_registration_options(user=user, existing_credentials=[])
    assert first["publicKey"]["challenge"] != second["publicKey"]["challenge"]
