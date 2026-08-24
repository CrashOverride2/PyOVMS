"""
Rendering for the operator-authored info box.

The content is Markdown written by an administrator and shown to every logged-in
user, so it is rendered in two places: the admin dashboard and the user dashboard.
Both had their own copy of the renderer, and the copies had drifted — the admin one
stripped `javascript:` hrefs, the user one did not. The weaker copy was the one
serving the larger audience.

One implementation, imported by both. The same reasoning as app.utils.two_factor:
a security rule that exists twice is a security rule that will eventually exist in
two different versions.
"""

import html
import logging
import re

logger = logging.getLogger(__name__)

try:
    import markdown
except ImportError:  # pragma: no cover - depends on the deployment's extras
    markdown = None
    logger.warning("The 'markdown' library is not installed. Info box will not render markdown.")

# Markdown emits links verbatim, so a scheme check has to happen after rendering.
# escape() above neutralises raw HTML, but `[x](javascript:alert(1))` is *valid
# Markdown* and becomes a real anchor.
_UNSAFE_HREF_RE = re.compile(r'href="\s*(?:javascript|data|vbscript)[^"]*"', re.IGNORECASE)


def render_safe_markdown(content: str) -> str:
    """Render Markdown with raw HTML escaped and dangerous URI schemes removed."""
    if not markdown or not content:
        return ""
    rendered = markdown.markdown(html.escape(content))
    return _UNSAFE_HREF_RE.sub('href="#"', rendered)
