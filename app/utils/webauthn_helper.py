"""
WebAuthn/FIDO2 authentication helper.
"""
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from typing import List, Dict, Any
import secrets
import json
from app.models.db import User, WebAuthnCredential
from app.config import settings


class WebAuthnHelper:
    """Helper class for WebAuthn operations."""

    def __init__(self, rp_id: str, rp_name: str, origin: str):
        """
        Initialize WebAuthn helper.

        Args:
            rp_id: Relying Party ID (usually your domain, e.g., "example.com")
            rp_name: Relying Party name (displayed to user)
            origin: Origin URL (e.g., "https://example.com")
        """
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin

    def generate_registration_options(
        self,
        user: User,
        existing_credentials: List[WebAuthnCredential],
        require_user_verification: bool = False,
        require_discoverable: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate WebAuthn registration options for a user.

        Args:
            user: User object
            existing_credentials: List of user's existing credentials to exclude
            require_user_verification: set for passwordless registrations, so the
                credential is capable of the PIN/biometric check its login demands.
            require_discoverable: set for passwordless registrations, so the credential
                is stored on the authenticator and the login can find it without being
                told it exists.

                A separate flag rather than a second reading of
                require_user_verification: the two answer different questions ("can it
                prove who is holding it" vs "can it be found without a hint"), they
                happen to coincide for the two roles that exist today, and quietly
                deriving one from the other is how a later UV-required 2FA credential
                would start demanding a resident key it has no use for.

        Returns:
            Dictionary with registration options wrapped in publicKey
        """
        # Exclude existing credentials
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=bytes.fromhex(cred.credential_id))
            for cred in existing_credentials
        ]

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=str(user.id).encode('utf-8'),
            user_name=user.username,
            user_display_name=user.full_name or user.username,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                # Must match what the corresponding login path demands. A passwordless
                # credential registered with PREFERRED may be UV-incapable, and the
                # passwordless login now rejects assertions without the UV flag — so
                # registering it here would hand the user a key that silently fails at
                # sign-in. The 2FA flow keeps PREFERRED: there the password was already
                # checked and possession is the job.
                user_verification=(
                    UserVerificationRequirement.REQUIRED if require_user_verification
                    else UserVerificationRequirement.PREFERRED
                ),
                # Passwordless credentials must be discoverable, so the authenticator
                # can find them without being told which ones exist. Without this the
                # login has to send an allowCredentials list, and since a passwordless
                # login has not identified the user yet, that list is *every*
                # passwordless credential on the server — handed to anyone who asks.
                #
                # DISCOURAGED rather than unset for 2FA: those are looked up by user id
                # after the password step, so they never need to be discoverable, and
                # demanding a resident key would burn one of the handful of slots a
                # hardware key has for no benefit.
                resident_key=(
                    ResidentKeyRequirement.REQUIRED if require_discoverable
                    else ResidentKeyRequirement.DISCOURAGED
                ),
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )

        # Wrap in publicKey for browser compatibility
        public_key = json.loads(options_to_json(options))

        if require_discoverable:
            # Ask the browser to report whether a resident key was actually created.
            # resident_key=REQUIRED above is a request, not a guarantee — an
            # authenticator may create a non-discoverable credential anyway, and the
            # login has to name those or their owner cannot sign in. credProps.rk is
            # the only way to learn which one we got.
            #
            # Injected into the serialised options because py_webauthn's
            # generate_registration_options() has no parameter for extensions; it only
            # parses them on the way back in.
            public_key["extensions"] = {"credProps": True}

        return {"publicKey": public_key}

    def verify_registration_response(
        self,
        credential: Dict[str, Any],
        expected_challenge: bytes,
    ) -> Dict[str, Any]:
        """
        Verify a WebAuthn registration response.

        Args:
            credential: Credential data from client
            expected_challenge: The challenge that was sent to the client

        Returns:
            Dictionary with verified credential data
        """
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
        )

        # Handle both bytes and str types (different library versions may return different types)
        credential_id = verification.credential_id
        if isinstance(credential_id, bytes):
            credential_id = credential_id.hex()

        credential_public_key = verification.credential_public_key
        if isinstance(credential_public_key, bytes):
            credential_public_key = credential_public_key.hex()

        aaguid = None
        if verification.aaguid:
            if isinstance(verification.aaguid, bytes):
                aaguid = verification.aaguid.hex()
            else:
                aaguid = verification.aaguid

        return {
            "credential_id": credential_id,
            "credential_public_key": credential_public_key,
            "sign_count": verification.sign_count,
            "aaguid": aaguid,
        }

    def generate_authentication_options(
        self,
        user_credentials: List[WebAuthnCredential],
        require_user_verification: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate WebAuthn authentication options.

        Args:
            user_credentials: Credentials to name in allowCredentials. An empty list
                means "name none of them": the authenticator is left to find a
                discoverable credential itself. The passwordless login relies on this
                to avoid disclosing which credentials exist — see ui/webauthn.py.
            require_user_verification: demand PIN or biometrics, not just a touch.

                Set for the *passwordless* flow, where the assertion is the entire
                login: with PREFERRED the authenticator may skip verification and
                report it, and the server used to accept that — so possession of the
                key alone produced a full session, no password and no second factor.
                That is single-factor authentication by a different name.

                Left off for the 2FA flow, where the password has already been
                checked and proving possession is exactly the job.

        Returns:
            Dictionary with authentication options wrapped in publicKey
        """
        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=bytes.fromhex(cred.credential_id),
                transports=[AuthenticatorTransport.USB, AuthenticatorTransport.NFC,
                           AuthenticatorTransport.BLE, AuthenticatorTransport.INTERNAL]
            )
            for cred in user_credentials
        ]

        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow_credentials if allow_credentials else None,
            user_verification=(
                UserVerificationRequirement.REQUIRED if require_user_verification
                else UserVerificationRequirement.PREFERRED
            ),
        )

        # Wrap in publicKey for browser compatibility
        return {"publicKey": json.loads(options_to_json(options))}

    def verify_authentication_response(
        self,
        credential: Dict[str, Any],
        expected_challenge: bytes,
        credential_public_key: bytes,
        credential_current_sign_count: int,
        require_user_verification: bool = False,
    ) -> Dict[str, Any]:
        """
        Verify a WebAuthn authentication response.

        Args:
            credential: Credential assertion from client
            expected_challenge: The challenge that was sent to the client
            credential_public_key: The stored public key for this credential
            credential_current_sign_count: Current sign count for this credential
            require_user_verification: reject an assertion whose UV flag is unset.

                Asking for REQUIRED in the options is only a request — the flag in
                the returned authenticator data is the fact. Without this the library
                defaults to False and never looks, so the request was advisory and a
                presence-only assertion sailed through.

        Returns:
            Dictionary with verification result including new sign count
        """
        # Build the allowed origins list: web origin plus any server-configured Android APK origins.
        # Never accept a client-supplied origin — the allowlist is server-side only.
        allowed_origins: List[str] = [self.origin]
        if settings.WEBAUTHN_TRUSTED_ANDROID_ORIGINS:
            allowed_origins.extend(settings.WEBAUTHN_TRUSTED_ANDROID_ORIGINS)

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self.rp_id,
            expected_origin=allowed_origins,
            credential_public_key=credential_public_key,
            credential_current_sign_count=credential_current_sign_count,
            require_user_verification=require_user_verification,
        )
        return {
            "new_sign_count": verification.new_sign_count,
            "verified": True,
        }


def generate_challenge() -> bytes:
    """Generate a random challenge for WebAuthn."""
    return secrets.token_bytes(32)


def get_webauthn_helper(rp_id: str, rp_name: str, origin: str) -> WebAuthnHelper:
    """Factory function to create WebAuthnHelper instance."""
    return WebAuthnHelper(rp_id=rp_id, rp_name=rp_name, origin=origin)
