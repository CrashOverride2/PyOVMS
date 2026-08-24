"""
Secret initializer for PyOVMS.

Called once at process start (from run.py) before app.config is loaded.
Generates a .env file from the template when none exists, and fills in any
secrets that are still at their placeholder values.
"""

import re
import secrets
import sys
from pathlib import Path

# Placeholder values that indicate a secret has never been customised.
_DEFAULT_MARKERS = (
    "change_this_for_production",
    "changeme_",
    "a_very_strong_mqtt_password_for_karto",
    "0gXIqS9Z0kZ-Yg7tJ2eX_rU8wH6vI9nL0fA3cE1bS2k=_change_this_strong_random_key",
    "placeholder",
)

# Keys we must generate on first run, with (generator_fn, env_key) pairs.
_SECRET_KEYS = [
    "SECRET_KEY_JWT",
    "SECRET_KEY_SESSION",
    "TOTP_ENCRYPTION_KEY",
    "JWT_PRIVATE_KEY",
    "JWT_PUBLIC_KEY",
    "MQTT_BACKEND_METRICS_SUB_PASS",
    "MQTT_BACKEND_NOTIFY_SUB_PASS",
    "MQTT_BACKEND_INTERACTIVE_PASS",
    "KARTO_MQTT_PASSWORD",
]

# The two JWT key halves must come from the same Ed25519 key, so they are generated
# together and memoised for the duration of the run.
_jwt_keypair: tuple[str, str] | None = None


def _jwt_keypair_values() -> tuple[str, str]:
    """(private_b64, public_b64) for a fresh Ed25519 key."""
    global _jwt_keypair
    if _jwt_keypair is None:
        import base64

        # Imported here rather than via app.jwt_keys: this module runs before .env
        # exists, and app.jwt_keys pulls in app.config, which would fail at that point.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        _jwt_keypair = (
            base64.b64encode(private_raw).decode(),
            base64.b64encode(public_raw).decode(),
        )
    return _jwt_keypair


def _gen_jwt_private() -> str:
    return _jwt_keypair_values()[0]


def _gen_jwt_public() -> str:
    return _jwt_keypair_values()[1]


def _gen_jwt_secret() -> str:
    return secrets.token_urlsafe(64)


def _gen_fernet_key() -> str:
    try:
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()
    except ImportError:
        # Fallback: URL-safe base64 of 32 bytes (structurally valid Fernet key)
        import base64
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def _gen_password() -> str:
    return secrets.token_urlsafe(32)


_GENERATORS = {
    "SECRET_KEY_JWT": _gen_jwt_secret,
    "SECRET_KEY_SESSION": _gen_jwt_secret,
    "TOTP_ENCRYPTION_KEY": _gen_fernet_key,
    "JWT_PRIVATE_KEY": _gen_jwt_private,
    "JWT_PUBLIC_KEY": _gen_jwt_public,
    "MQTT_BACKEND_METRICS_SUB_PASS": _gen_password,
    "MQTT_BACKEND_NOTIFY_SUB_PASS": _gen_password,
    "MQTT_BACKEND_INTERACTIVE_PASS": _gen_password,
    "KARTO_MQTT_PASSWORD": _gen_password,
}


def _is_default(value: str) -> bool:
    return any(marker in value for marker in _DEFAULT_MARKERS)


def _parse_env_file(text: str) -> dict[str, str]:
    """Return key→raw-value mapping (preserves quoting in values)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        result[key.strip()] = val.strip().strip('"').strip("'")
    return result


def _replace_value_in_text(text: str, key: str, new_value: str) -> str:
    """Replace the value for *key* in the env-file text, preserving formatting."""
    # [ \t]* rather than \s*: \s matches newlines, so on a key whose value is empty the
    # pattern ran past the end of the line and consumed the NEXT declaration as this
    # key's value. .env-template ships JWT_PRIVATE_KEY= and JWT_PUBLIC_KEY= on adjacent
    # empty lines, so first-run generation destroyed the public key line, left the
    # private one empty, and every fresh install aborted at startup on an unusable
    # session signing key.
    pattern = re.compile(
        r'^(' + re.escape(key) + r'[ \t]*=[ \t]*)["\']?[^"\'#\n]*["\']?',
        re.MULTILINE,
    )
    def _substitute(match: re.Match) -> str:
        # Callable replacement: a generated secret is arbitrary text, and \g / backslash
        # sequences in it must not be interpreted as group references.
        out = match.group(1) + new_value
        # The value pattern stops at '#' but eats the spaces in front of it, so a line
        # written as `KEY=value  # why` would come back as `KEY=<secret># why` — the
        # comment glued onto the secret, and read back as part of it.
        if text[match.end():match.end() + 1] == "#":
            out += " "
        return out

    updated, count = pattern.subn(_substitute, text)
    if count == 0:
        # Key not present yet – append it
        updated = text.rstrip("\n") + f"\n{key}={new_value}\n"
    return updated


def ensure_secrets(project_root: Path | None = None) -> None:
    """
    Ensure the .env file exists and all critical secrets have been customised.

    If .env is absent, it is created from .env-template (if available) with
    secure random values substituted for every placeholder.

    If .env exists but some secrets still have placeholder values, those are
    replaced in-place and the user is warned to restart.
    """
    if project_root is None:
        # Assume run.py lives at the project root – resolve relative to this file.
        project_root = Path(__file__).resolve().parent.parent

    env_path = project_root / ".env"
    template_path = project_root / ".env-template"

    if not env_path.exists():
        _create_env_from_scratch(env_path, template_path)
    else:
        _patch_existing_env(env_path)


def _create_env_from_scratch(env_path: Path, template_path: Path) -> None:
    print("=" * 70, file=sys.stderr)
    print("PyOVMS: No .env file found. Generating one with secure secrets…", file=sys.stderr)

    if template_path.exists():
        content = template_path.read_text(encoding="utf-8")
    else:
        content = _minimal_env_template()

    for key, gen in _GENERATORS.items():
        new_val = gen()
        content = _replace_value_in_text(content, key, new_val)

    env_path.write_text(content, encoding="utf-8")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass

    print(f"  Created: {env_path}", file=sys.stderr)
    print("  Secure random secrets have been generated.", file=sys.stderr)
    print("  Review and complete the remaining settings before production use.", file=sys.stderr)
    print("  IMPORTANT: Keep .env secure – never commit it to version control!", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


def _patch_existing_env(env_path: Path) -> None:
    content = env_path.read_text(encoding="utf-8")
    values = _parse_env_file(content)

    weak_keys = [
        key for key in _SECRET_KEYS
        # An empty value counts as missing: _is_default("") is False, so without this
        # an upgraded .env that declares JWT_PRIVATE_KEY= would never get one generated.
        if key not in values or not values.get(key, "").strip() or _is_default(values.get(key, ""))
    ]

    # Never regenerate one half of the key pair on its own — the halves would no longer
    # match and every session would fail to verify.
    if {"JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY"} & set(weak_keys):
        for key in ("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY"):
            if key not in weak_keys:
                weak_keys.append(key)

    if not weak_keys:
        return

    print("=" * 70, file=sys.stderr)
    print("PyOVMS: Missing or placeholder secrets detected in .env:", file=sys.stderr)
    for key in weak_keys:
        new_val = _GENERATORS[key]()
        content = _replace_value_in_text(content, key, new_val)
        action = "Added missing" if key not in values else "Replaced placeholder for"
        print(f"  {action}: {key}", file=sys.stderr)

    env_path.write_text(content, encoding="utf-8")
    try:
        env_path.chmod(0o600)
    except OSError:
        pass

    print("  Secrets have been updated in .env.", file=sys.stderr)
    print("  Please RESTART the server for the new secrets to take effect.", file=sys.stderr)
    print("  NOTE: Existing JWT sessions and TOTP tokens will be invalidated.", file=sys.stderr)
    if "JWT_PUBLIC_KEY" in weak_keys:
        new_public = _parse_env_file(content).get("JWT_PUBLIC_KEY", "").strip().strip('"')
        print("", file=sys.stderr)
        print("  A new session signing key pair was generated. If you run the Karto", file=sys.stderr)
        print("  service, copy this PUBLIC key into its karto.env — Karto verifies", file=sys.stderr)
        print("  tokens and must never receive the private key:", file=sys.stderr)
        print(f"    JWT_PUBLIC_KEY={new_public}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)


def _minimal_env_template() -> str:
    return """\
# PyOVMS Configuration – auto-generated
# IMPORTANT: Keep this file secure and never commit it to version control!

DATABASE_URL="sqlite:///./ovms_py.db"
SERVER_HOST="0.0.0.0"
HTTP_PORT=8000
TCP_PORT=6867
TCP_SSL_PORT=6870
SERVER_BASE_URL="http://localhost:8000"
FORCE_SECURE_COOKIES=True

SECRET_KEY_JWT=placeholder
SECRET_KEY_SESSION=placeholder
TOTP_ENCRYPTION_KEY=placeholder
MQTT_BACKEND_METRICS_SUB_PASS=placeholder
MQTT_BACKEND_NOTIFY_SUB_PASS=placeholder
MQTT_BACKEND_INTERACTIVE_PASS=placeholder
KARTO_MQTT_PASSWORD=placeholder
"""
