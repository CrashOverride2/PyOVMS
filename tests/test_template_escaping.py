"""
Regression tests for C-4: the `tojson` filter must HTML-escape.

History: the XSS fix from the previous audit round replaced `json.dumps()` in the route
with `| tojson` in the template — but app/routers/ui/__init__.py overrode `tojson` with
`Markup(json.dumps(...))`, which escapes nothing. The fix was correct and had no effect,
and both audits missed it because they took the filter name for its semantics. These
tests assert the behaviour rather than the spelling.
"""

import json

import pytest

from app.routers.ui import templates, tojson_filter

BREAKOUT = "</script><img src=x onerror=alert(1)>"


def _render(value):
    """Run a value through the filter exactly as a template would."""
    return str(tojson_filter(None, value))


def test_tojson_escapes_script_breakout():
    out = _render({"units": BREAKOUT})
    assert "</script>" not in out, "raw </script> in tojson output would break out of the script block"
    assert "\\u003c" in out
    # The data must survive the escaping, not be dropped.
    assert json.loads(out)["units"] == BREAKOUT


def test_tojson_escapes_single_quote_for_attribute_context():
    # Templates embed |tojson inside single-quoted HTML attributes
    # (profile.html, users_management.html, autoprovision_management.html).
    out = _render("it's")
    assert "'" not in out
    assert "\\u0027" in out


def test_tojson_escapes_ampersand_and_gt():
    out = _render("a & b > c")
    assert "&" not in out and ">" not in out


@pytest.mark.parametrize("payload", [
    {"v3_metrics": {BREAKOUT: BREAKOUT}},          # attacker controls keys too
    [BREAKOUT],
    BREAKOUT,
])
def test_tojson_escapes_nested_and_scalar_payloads(payload):
    assert "</script>" not in _render(payload)


def test_tojson_filter_is_the_one_registered_on_the_template_env():
    """
    The override must actually be installed on the environment the app renders with.

    It is registered in app.main, not in app.routers.ui, so importing only the UI
    package leaves Jinja's builtin in place. Import the app to assert the real wiring —
    otherwise this suite would keep passing if someone dropped the registration.
    """
    import app.main  # noqa: F401  (import for its side effect: filter registration)

    assert templates.env.filters["tojson"] is tojson_filter


def test_vehicle_detail_template_renders_hostile_metrics_safely():
    """End-to-end through Jinja, the way the real page does it."""
    tpl = templates.env.from_string("const initialLiveData = {{ initial_live_data | tojson | safe }};")
    rendered = tpl.render(initial_live_data={"units": BREAKOUT})
    assert "</script>" not in rendered
