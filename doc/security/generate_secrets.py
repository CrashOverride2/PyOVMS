#!/usr/bin/env python3
"""
Secret Key Generation Utility for PyOVMS

This script generates secure random keys for production deployment.
Run this script to generate a .env file with secure secrets.

Usage:
    python generate_secrets.py              # Creates .env with secure keys
    python generate_secrets.py --show       # Shows keys without writing file
    python generate_secrets.py --output custom.env  # Custom output file
"""

import os
import re
import secrets
import base64
import argparse
from pathlib import Path
from cryptography.fernet import Fernet

# Placeholder fragments that must not survive into the generated .env. Kept in sync with
# app/secret_initializer.py's _DEFAULT_MARKERS, which is what run.py checks on startup.
PLACEHOLDER_MARKERS = (
    "change_this_for_production",
    "changeme_",
    "a_very_strong_mqtt_password_for_karto",
    "_change_this_strong_random_key",
    "placeholder",
)

# Secrets no longer left for run.py to fill in. They used to be, which made this script
# insufficient on its own: a container that mounts .env read-only (the server runs as an
# unprivileged user and cannot patch it) aborted on the empty JWT_PRIVATE_KEY. Everything
# app/secret_initializer.py generates is now generated here too, so a .env from this
# script is complete and needs no write access at runtime.
NOT_GENERATED_HERE = ()


def generate_jwt_secret(length: int = 64) -> str:
    """Generate a secure random secret for JWT signing."""
    return secrets.token_urlsafe(length)


def generate_fernet_key() -> str:
    """Generate a Fernet-compatible encryption key (32 bytes, base64-encoded)."""
    return Fernet.generate_key().decode('utf-8')


def generate_mqtt_password(length: int = 32) -> str:
    """Generate a secure MQTT password."""
    return secrets.token_urlsafe(length)


def generate_session_secret(length: int = 64) -> str:
    """Generate a secure session secret."""
    return secrets.token_urlsafe(length)


def generate_jwt_keypair() -> tuple:
    """
    Generate the Ed25519 session signing pair as (private_b64, public_b64).

    Must stay byte-for-byte compatible with app/jwt_keys.py, which decodes both halves
    with validate=True and requires exactly 32 raw bytes. Deliberately duplicated rather
    than imported: this script runs before dependencies like pydantic-settings are
    guaranteed to be importable, and app.jwt_keys pulls in app.config.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode(), base64.b64encode(public_raw).decode()


def read_env_template() -> str:
    """
    Read the .env-template file from the repository root.

    It was looked up next to this script, in doc/security/, where it has never
    existed. read_env_template() therefore always returned "" and the minimal
    fallback branch always ran — which omits SECRET_KEY_SESSION, and left the
    MQTT_PASSWD_FILE / MQTT_ACL_FILE lines absent so install.sh's `sed` on
    `^#MQTT_PASSWD_FILE=` matched nothing. The result was a working-looking install
    with the broker password and ACL sync silently switched off.

    Failing loudly now: a silent fallback is what hid this for as long as it did.
    """
    template_path = Path(__file__).resolve().parents[2] / '.env-template'
    if not template_path.exists():
        raise SystemExit(
            f"FATAL: .env-template not found at {template_path}. Run this script from "
            f"a complete checkout — generating a partial .env silently disables the "
            f"MQTT credential sync."
        )
    return template_path.read_text()


def _set_env_value(text: str, key: str, value: str) -> str:
    """
    Replace the value assigned to *key*, whether or not the template quotes it.

    Matching the whole `KEY=placeholder` literal is what broke here: every assignment in
    .env-template is double-quoted, so all six str.replace() calls matched nothing and
    this script wrote out a .env in which every secret was still its placeholder — while
    printing "Secure secrets generated". Anchor on the key instead, and let
    _assert_no_placeholders() catch it if this ever stops matching again.

    A commented-out assignment (`#KARTO_MQTT_PASSWORD="..."`) is uncommented: a generated
    secret that stays disabled is not what the caller asked for.
    """
    pattern = re.compile(
        r'^[ \t]*#?[ \t]*(' + re.escape(key) + r')[ \t]*=[ \t]*.*$',
        re.MULTILINE,
    )
    text, count = pattern.subn(rf'\g<1>="{value}"', text, count=1)
    if count == 0:
        raise SystemExit(
            f"FATAL: {key} does not appear in .env-template. Refusing to write a .env "
            f"that silently omits it."
        )
    return text


def _assert_no_placeholders(content: str) -> None:
    """Fail loudly if a secret this script is responsible for is still a placeholder."""
    offenders = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key = stripped.split('=', 1)[0].strip()
        if key in NOT_GENERATED_HERE:
            continue  # run.py fills these in on first start
        if any(marker in stripped for marker in PLACEHOLDER_MARKERS):
            offenders.append(key)
    if offenders:
        raise SystemExit(
            "FATAL: these secrets are still at their placeholder values after "
            f"generation: {', '.join(offenders)}. Refusing to write an insecure .env."
        )


def generate_env_content() -> str:
    """Generate .env file content with secure secrets."""

    content = read_env_template()
    jwt_private, jwt_public = generate_jwt_keypair()

    for key, value in (
        ('SECRET_KEY_JWT', generate_jwt_secret()),
        ('SECRET_KEY_SESSION', generate_session_secret()),
        ('JWT_PRIVATE_KEY', jwt_private),
        ('JWT_PUBLIC_KEY', jwt_public),
        ('TOTP_ENCRYPTION_KEY', generate_fernet_key()),
        ('MQTT_BACKEND_METRICS_SUB_PASS', generate_mqtt_password()),
        ('MQTT_BACKEND_NOTIFY_SUB_PASS', generate_mqtt_password()),
        ('MQTT_BACKEND_INTERACTIVE_PASS', generate_mqtt_password()),
        ('KARTO_MQTT_PASSWORD', generate_mqtt_password()),
    ):
        content = _set_env_value(content, key, value)

    _assert_no_placeholders(content)
    return content


def main():
    parser = argparse.ArgumentParser(
        description='Generate secure secrets for PyOVMS deployment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--output', '-o',
        default='.env',
        help='Output file path (default: .env)'
    )
    parser.add_argument(
        '--show', '-s',
        action='store_true',
        help='Show generated secrets without writing to file'
    )
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Overwrite existing .env file without prompting'
    )

    args = parser.parse_args()

    # Generate content
    env_content = generate_env_content()

    if args.show:
        print(env_content)
        return

    # Check if file exists
    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        response = input(f"{output_path} already exists. Overwrite? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return

    # Write to file, then restrict it before anything else can read it.
    #
    # This used to land at the default umask (0644). install.sh corrects it
    # afterwards, but only there — anyone running this script directly, which the
    # documentation invites, got a world-readable file containing the JWT signing
    # key, the TOTP encryption key and every broker password.
    output_path.write_text(env_content)
    os.chmod(output_path, 0o600)
    print(f"✅ Secure secrets generated and saved to: {output_path} (mode 0600)")
    print("⚠️  IMPORTANT: Keep this file secure and add it to .gitignore!")
    print("⚠️  BACKUP: Store a secure backup of this file in a safe location")

    # Security reminder
    print("\n🔒 Security Checklist:")
    print("   1. Ensure .env is in your .gitignore file")
    print("   2. Set restrictive file permissions: chmod 600 .env")
    print("   3. Create a secure backup")
    print("   4. Configure remaining settings in .env (database, email, etc.)")


if __name__ == '__main__':
    main()
