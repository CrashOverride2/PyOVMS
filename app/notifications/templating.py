"""Jinja environments and translation loading for outbound mail.

Two environments, for two different kinds of input:

* `template_env` renders files under app/templates/email/. It autoescapes, because those
  templates interpolate vehicle names, full names and usernames.
* `_inline_template_env` renders template *strings* passed in by callers. It is
  sandboxed and does not autoescape — those strings are mail subjects and complete
  pre-built HTML bodies, not fragments.

Telling the two apart is `is_template_file()`, which is load-bearing: get it wrong and a
subject is looked up as a file, raises TemplateNotFound, and the notification silently
disappears.
"""

import logging
from functools import lru_cache
from pathlib import Path
from typing import Callable

from babel.support import Translations
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from app.config import settings

logger = logging.getLogger(__name__)

# Resolved from this file rather than from the process working directory. The old
# "./app/templates/" only worked when the server happened to be started from the repo
# root; anywhere else the environment came up empty and every templated mail was lost.
TEMPLATE_SEARCHPATH = Path(__file__).resolve().parents[1] / "templates"

_TEMPLATE_FILE_SUFFIXES = (".txt", ".html", ".htm", ".xml")

try:
    template_loader = FileSystemLoader(searchpath=str(TEMPLATE_SEARCHPATH))
    # autoescape is off by default in a bare Environment (unlike the UI's
    # Jinja2Templates). The mail templates interpolate vehicle_name, full_name and
    # owner_username, none of which are character-restricted — without escaping, a
    # vehicle named '<a href="https://evil/">Confirm</a>' turns the lifecycle warning
    # that goes to every admin into a phishing mail sent from our own domain.
    template_env = Environment(
        loader=template_loader,
        autoescape=select_autoescape(["html", "htm", "xml"]),
        auto_reload=False,  # templates ship with the code; stat()ing them per render is waste
    )
except Exception as e:
    logger.error(f"Could not initialize Jinja2 environment for email templates: {e}")
    template_env = None

# Inline (non-file) templates are rendered through a sandbox. They are developer-authored
# constants today, but callers interpolate vehicle IDs, usernames and IPs into them before
# they arrive here, so the sandbox keeps a future validator slip from becoming template
# injection. autoescape stays off on purpose: these strings are mail subjects and complete
# pre-built HTML bodies, not fragments assembled from untrusted values.
_inline_template_env = SandboxedEnvironment(autoescape=False)


def is_template_file(name: str) -> bool:
    """
    Decide whether a caller passed a template *file path* or an inline template string.

    The previous test was `name.startswith('email/') or '.' in name`. Every IPv4 address
    contains a dot, so the subject "OVMS Security Alert: IP Blocked - 10.0.0.1" was looked
    up as a template path; the resulting TemplateNotFound was swallowed by the per-admin
    except block and the IP-block alert was never delivered to anyone. Require both the
    directory prefix and a known suffix instead of guessing from punctuation.
    """
    return (
        name.startswith("email/")
        and name.endswith(_TEMPLATE_FILE_SUFFIXES)
        and "\n" not in name
    )


@lru_cache(maxsize=64)
def _compile_inline(source: str):
    """Compile an inline template once.

    The admin fan-out renders the same three strings for every admin; without this each
    one was parsed and compiled again per recipient.
    """
    return _inline_template_env.from_string(source)


def render_source(source: str, template_vars: dict) -> str:
    """Render one notification template, from a file or from an inline string."""
    if is_template_file(source):
        if template_env is None:
            raise RuntimeError("Jinja2 template environment is not available.")
        return template_env.get_template(source).render(template_vars)
    return _compile_inline(source).render(template_vars)


def render_file(name: str, template_vars: dict) -> str:
    """Render a template file under app/templates/."""
    if template_env is None:
        raise RuntimeError("Jinja2 template environment is not available.")
    return template_env.get_template(name).render(template_vars)


def N_(message: str) -> str:
    """Mark a string for extraction without translating it here.

    Babel's standard no-op marker, and one of its default keywords, so wrapping a
    literal in it is enough to put the string in messages.pot. It is needed wherever the
    English text is written down somewhere the extractor cannot see a `_()` call: mail
    subjects handed to `_send_templated_email()` as plain keys, and the subject
    *templates* embedded as Python strings, where the `{{ _('…') }}` inside is Jinja and
    the file is scanned as Python.

    Translation still happens at send time, against the recipient's locale — this only
    guarantees the catalogue has an entry to look up.
    """
    return message


@lru_cache(maxsize=16)
def _load_translations(locale: str) -> Translations:
    return Translations.load(settings.BABEL_TRANSLATION_DIRECTORIES, [locale])


def get_gettext(locale: str = None) -> Callable[[str], str]:
    """A gettext callable for `locale`, falling back to identity.

    Cached: Translations.load() reads and parses the .mo catalogue from disk, and the
    admin fan-out called it once per admin per notification.

    The locale is validated against SUPPORTED_LOCALES before it reaches the cache, both
    because an unsupported one has no catalogue anyway and because the value can come
    from a user profile — an unbounded key would let it grow the cache.
    """
    if not locale or locale not in settings.SUPPORTED_LOCALES:
        locale = settings.BABEL_DEFAULT_LOCALE
    try:
        return _load_translations(locale).gettext
    except Exception as e:
        logger.warning(f"Failed to load translations for locale '{locale}': {e}")
        return lambda text: text


# Backwards-compatible alias for the old module-level name.
_is_template_file = is_template_file
