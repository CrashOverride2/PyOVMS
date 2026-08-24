"""Outbound mail is translated all the way through, subject included.

Two gaps this pins shut, both of which fail silently — the mail still goes out, just in
the wrong language, and only for the locales nobody on the team reads:

  * A subject template embedded in a Python module (`"🚨 {{ _('…') }} - {{ ip_address }}"`)
    resolves its `_()` at render time, but the file is scanned as *Python*, so pybabel
    never sees the call. The msgid is missing from the catalogue and gettext falls back
    to English — under a German-language body.
  * The `.txt` half of every multipart mail was not covered by babel.cfg at all, so a
    recipient reading plain text got English while the HTML alternative beside it was
    translated.

Both are configuration-shaped, which is why they are tested rather than reviewed.
"""

import ast
import re
from pathlib import Path

import pytest
from babel.messages.pofile import read_po

from app.config import settings

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / "app" / "templates" / "email"
NOTIFICATIONS_DIR = REPO_ROOT / "app" / "notifications"

# `{{ _('…') }}` / `{{ _("…") }}`, the only gettext form these templates use.
_JINJA_GETTEXT = re.compile(r"""\{\{-?\s*_\(\s*(['"])(?P<msgid>.+?)\1\s*\)""", re.S)

TRANSLATED_LOCALES = [loc for loc in settings.SUPPORTED_LOCALES if loc != "en"]


def _catalog(locale: str):
    path = REPO_ROOT / "app" / "translations" / locale / "LC_MESSAGES" / "messages.po"
    with path.open("rb") as fh:
        return read_po(fh, locale=locale)


@pytest.fixture(scope="module")
def catalogs():
    return {locale: _catalog(locale) for locale in TRANSLATED_LOCALES}


def _msgids_in(text: str) -> set:
    return {m.group("msgid") for m in _JINJA_GETTEXT.finditer(text)}


def _mail_template_msgids() -> set:
    found = set()
    for path in sorted(TEMPLATE_DIR.iterdir()):
        if path.suffix in (".txt", ".html"):
            found |= _msgids_in(path.read_text(encoding="utf-8"))
    return found


def _code_string_literals(source: str):
    """Every string literal in `source` except docstrings.

    Docstrings are excluded deliberately: this file and the modules it checks *describe*
    the `{{ _('…') }}` pattern in prose, and a scanner that reads those would report the
    ellipsis in the description as an untranslated message.
    """
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and id(node) not in docstrings:
            yield node.value


def _embedded_template_msgids() -> set:
    """Msgids in Jinja templates written as Python string literals.

    These are the ones pybabel cannot reach on its own — see N_() in templating.py.
    """
    paths = list(NOTIFICATIONS_DIR.rglob("*.py")) + [REPO_ROOT / "app" / "security_manager.py"]
    found = set()
    for path in paths:
        for literal in _code_string_literals(path.read_text(encoding="utf-8")):
            found |= _msgids_in(literal)
    return found


def test_the_mail_templates_actually_use_gettext():
    """A guard on the guard: if the regex stops matching, everything below passes vacuously."""
    assert len(_mail_template_msgids()) > 20


@pytest.mark.parametrize("locale", TRANSLATED_LOCALES)
def test_every_mail_template_string_is_translated(locale, catalogs):
    catalog = catalogs[locale]
    missing = sorted(
        msgid for msgid in _mail_template_msgids()
        if catalog.get(msgid) is None or not catalog.get(msgid).string
    )
    assert not missing, (
        f"{locale}: {len(missing)} mail template string(s) have no translation. "
        f"Re-run `pybabel extract`/`update` and fill them in: {missing[:5]}"
    )


@pytest.mark.parametrize("locale", TRANSLATED_LOCALES)
def test_subjects_embedded_in_python_are_translated(locale, catalogs):
    """The N_() markers exist for exactly these; without them the subject stays English."""
    catalog = catalogs[locale]
    missing = sorted(
        msgid for msgid in _embedded_template_msgids()
        if catalog.get(msgid) is None or not catalog.get(msgid).string
    )
    assert not missing, (
        f"{locale}: subject msgid(s) embedded in Python are not in the catalogue. "
        f"Add an N_(\"…\") marker next to them and re-extract: {missing}"
    )


@pytest.mark.parametrize("locale", TRANSLATED_LOCALES)
def test_the_subject_keys_passed_to_send_are_translated(locale, catalogs):
    """The plain-string subject keys handed to _send_templated_email()."""
    from app.notifications.mail import user as user_mail

    keys = {
        m.group("msgid")
        for m in re.finditer(
            r"""N_\(\s*(['"])(?P<msgid>.+?)\1\s*\)""",
            Path(user_mail.__file__).read_text(encoding="utf-8"),
        )
    }
    assert keys, "no marked subject keys found — did the N_() wrapping get removed?"

    catalog = catalogs[locale]
    missing = sorted(k for k in keys if catalog.get(k) is None or not catalog.get(k).string)
    assert not missing, f"{locale}: untranslated mail subject(s): {missing}"


@pytest.mark.parametrize("locale", TRANSLATED_LOCALES)
def test_placeholders_survive_translation(locale, catalogs):
    """A translation that drops or renames %(name)s raises at render time, in production."""
    placeholder = re.compile(r"%\([a-zA-Z_]+\)[sdifr]")
    broken = []
    for message in catalogs[locale]:
        if not message.id or not message.string or not isinstance(message.string, str):
            continue
        if set(placeholder.findall(message.id)) != set(placeholder.findall(message.string)):
            broken.append(message.id)
    assert not broken, f"{locale}: placeholder mismatch in {broken}"


def test_the_plain_text_half_is_extracted_too():
    """babel.cfg must cover .txt, or every plain-text mail body silently stays English."""
    config = (REPO_ROOT / "babel.cfg").read_text(encoding="utf-8")
    assert "app/templates/**.txt" in config
