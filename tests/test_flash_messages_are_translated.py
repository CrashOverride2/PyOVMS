"""
Every flash message a UI route emits must go through gettext.

These are the `?success_message=` / `?error_message=` / `?info_message=` strings that a
redirecting route writes into the query string for the next page to display. They were
English literals while the page around them was translated, which is the one place the
usual review misses: the page renders correctly in German and the single line at the top
of it does not, and no test looked at a Location header.

Two properties, checked against the source rather than by rendering every route:

  * the value is never a bare literal — it is `{quote_plus(...)}` around a `_()` call, an
    exception detail, or a variable built earlier;
  * a message that interpolates uses a **named placeholder** and `%`, never an f-string.
    An f-string is formatted before gettext sees it, so the catalogue lookup is a
    different string on every call and silently misses every time — the failure looks
    exactly like a missing translation, and re-running pybabel does not fix it.

The gettext calls themselves are covered by `scripts/update_translations.sh --check`,
which fails when a msgid is missing from the catalogues.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
UI_DIR = REPO_ROOT / "app" / "routers" / "ui"

ROUTERS = sorted(p for p in UI_DIR.glob("*.py") if p.name != "__init__.py")

# `?success_message=` and everything up to the next parameter or the end of the string.
FLASH = re.compile(r'[?&](?:success|error|info)_message=([^"&]*)')


def _flash_values(path):
    """(line number, value) for every flash assignment in the file."""
    out = []
    for lineno, line in enumerate(path.read_text().split("\n"), 1):
        for m in FLASH.finditer(line):
            out.append((lineno, m.group(1)))
    return out


@pytest.mark.parametrize("path", ROUTERS, ids=lambda p: p.name)
def test_no_bare_english_literal_in_a_flash_message(path):
    """
    A flash value must be an interpolation, not prose. `?error_message=User not found.`
    is the shape this catches: it renders as English on a German page.
    """
    offenders = [
        (lineno, value)
        for lineno, value in _flash_values(path)
        if value and not value.startswith("{")
    ]
    assert offenders == [], (
        f"{path.name}: flash message written as a literal. Wrap it: "
        "?error_message={quote_plus(_('...'))}\n"
        + "\n".join(f"  line {n}: {v!r}" for n, v in offenders)
    )


@pytest.mark.parametrize("path", ROUTERS, ids=lambda p: p.name)
def test_no_fstring_inside_a_translated_flash_message(path):
    """
    `_(f'Vehicle {vid} added.')` looks translated and never is — see the module
    docstring. The named-placeholder form is `_("Vehicle %(id)s added.") % {...}`.
    """
    src = path.read_text()
    offenders = [
        m.group(0)[:80]
        for m in re.finditer(r"_\(\s*f['\"]", src)
    ]
    assert offenders == [], (
        f"{path.name}: gettext called with an f-string, which is formatted before the "
        f"lookup happens and therefore never matches a catalogue entry: {offenders}"
    )


def test_the_guard_sees_the_routers_it_thinks_it_does():
    """A path typo here would make both tests above pass by checking nothing."""
    assert len(ROUTERS) >= 10, f"only found {len(ROUTERS)} UI routers under {UI_DIR}"
    total = sum(len(_flash_values(p)) for p in ROUTERS)
    assert total > 100, (
        f"only {total} flash messages found across the UI routers — the regex no longer "
        "matches how they are written, so these tests are checking nothing"
    )
