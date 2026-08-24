"""
Regression tests for first-run secret generation.

`.env-template` is not just documentation — `run.py` copies it and fills the placeholders
in, so a defect here is not a cosmetic one: it lands on every fresh install, and only on
fresh installs, which is exactly the case no existing deployment ever exercises.

The bug these tests pin: the substitution pattern used `\\s*` around the `=`, and `\\s`
matches newlines. For a key whose value is empty the match therefore ran past the end of
its own line and swallowed the *next* declaration as the value. `.env-template` ships
`JWT_PRIVATE_KEY=` and `JWT_PUBLIC_KEY=` on adjacent empty lines, so generating the
private key destroyed the public key's line, left the private key empty, and the server
aborted at startup with "session signing key is unusable" — every single new install.
"""

import pathlib
import re

import pytest

from app.secret_initializer import (
    _GENERATORS,
    _SECRET_KEYS,
    _parse_env_file,
    _replace_value_in_text,
    ensure_secrets,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# --- the substitution itself ----------------------------------------------------

def test_empty_value_does_not_swallow_the_following_line():
    text = "JWT_PRIVATE_KEY=\nJWT_PUBLIC_KEY=\nSECRET_KEY_SESSION=keep\n"

    text = _replace_value_in_text(text, "JWT_PRIVATE_KEY", "PRIV==")
    text = _replace_value_in_text(text, "JWT_PUBLIC_KEY", "PUB==")

    values = _parse_env_file(text)
    assert values["JWT_PRIVATE_KEY"] == "PRIV=="
    assert values["JWT_PUBLIC_KEY"] == "PUB=="
    assert values["SECRET_KEY_SESSION"] == "keep"
    # Each key keeps its own line — nothing appended, nothing destroyed.
    assert text.count("JWT_PUBLIC_KEY=") == 1


def test_replacement_does_not_interpret_backslash_escapes():
    """A generated secret is arbitrary text, not a regex replacement template."""
    out = _replace_value_in_text("K=old\n", "K", r"a\g<1>b\\c")
    assert out == "K=a\\g<1>b\\\\c\n"


def test_missing_key_is_appended_once():
    out = _replace_value_in_text("OTHER=1\n", "NEW_KEY", "v")
    assert _parse_env_file(out)["NEW_KEY"] == "v"
    assert out.count("NEW_KEY=") == 1


def test_quoted_and_spaced_declarations_are_replaced_in_place():
    text = 'A = "old"\nB=old\n'
    text = _replace_value_in_text(text, "A", "newA")
    text = _replace_value_in_text(text, "B", "newB")
    values = _parse_env_file(text)
    assert values["A"] == "newA"
    assert values["B"] == "newB"
    assert text.count("\n") == 2  # no lines gained or lost


def test_trailing_comment_is_not_glued_onto_the_secret():
    """
    The value pattern stops at '#' but eats the spaces before it, so without a separator
    the comment ends up inside the value. No secret in `.env-template` currently carries
    an inline comment — this keeps adding one from silently corrupting it.
    """
    out = _replace_value_in_text("B=old  # why\n", "B", "SECRET")
    assert out == "B=SECRET # why\n"


# --- end to end, against the shipped template -----------------------------------

def test_env_generated_from_template_has_every_secret(tmp_path):
    """
    The published `.env-template` plus `ensure_secrets()` must yield a startable config.

    This is the exact path `run.py` takes on a fresh clone.
    """
    (tmp_path / ".env-template").write_text(
        (REPO_ROOT / ".env-template").read_text(encoding="utf-8"), encoding="utf-8"
    )

    ensure_secrets(project_root=tmp_path)

    values = _parse_env_file((tmp_path / ".env").read_text(encoding="utf-8"))
    for key in _SECRET_KEYS:
        assert values.get(key, "").strip(), f"{key} was not generated"
        assert "change_this" not in values[key]
        assert "placeholder" not in values[key]
        assert "changeme" not in values[key]


def test_generated_keypair_halves_belong_together(tmp_path):
    """A mismatched pair verifies nothing — every session would fail to authenticate."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    (tmp_path / ".env-template").write_text(
        (REPO_ROOT / ".env-template").read_text(encoding="utf-8"), encoding="utf-8"
    )
    ensure_secrets(project_root=tmp_path)
    values = _parse_env_file((tmp_path / ".env").read_text(encoding="utf-8"))

    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(values["JWT_PRIVATE_KEY"]))
    derived = base64.b64encode(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()
    assert derived == values["JWT_PUBLIC_KEY"]


def test_env_file_is_not_world_readable(tmp_path):
    (tmp_path / ".env-template").write_text(
        (REPO_ROOT / ".env-template").read_text(encoding="utf-8"), encoding="utf-8"
    )
    ensure_secrets(project_root=tmp_path)
    assert (tmp_path / ".env").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("key", sorted(_SECRET_KEYS))
def test_template_declares_every_generated_secret(key):
    """
    A secret the generator knows about but the template never mentions gets appended to
    the end of the file, far from its documentation. Keep the two in step.
    """
    template = (REPO_ROOT / ".env-template").read_text(encoding="utf-8")
    assert re.search(rf'^#?\s*{re.escape(key)}\s*=', template, re.MULTILINE), (
        f"{key} is generated by secret_initializer but absent from .env-template"
    )


def test_every_secret_key_has_a_generator():
    assert set(_SECRET_KEYS) == set(_GENERATORS)
