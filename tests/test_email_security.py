"""
Regression tests for the outbound mail path.

H-16  The mail Jinja environment had autoescape off (unlike the UI's Jinja2Templates),
      so vehicle_name / full_name / owner_username went into admin mails unescaped —
      a vehicle named '<a href="https://evil/">Confirm</a>' turns the lifecycle warning
      into a phishing mail sent from our own domain.
H-15  SMTP_SSL()/starttls() without an ssl context disable certificate verification.
M-21  The "is this a file or an inline template?" test was `'.' in name`. Every IPv4
      contains a dot, so the IP-block alert was looked up as a template path, raised
      TemplateNotFound, and was swallowed — admins were never notified of any block.
"""

import inspect

import pytest

from app import notifications


# --- H-16: autoescape ------------------------------------------------------------

def test_mail_template_environment_autoescapes_html():
    env = notifications.template_env
    assert env is not None
    assert env.autoescape, "mail templates must autoescape; they interpolate user-controlled names"


def test_hostile_vehicle_name_is_escaped_in_a_rendered_mail_template():
    # Assert against a real template file: select_autoescape keys off the filename, so
    # from_string() would not exercise the path the application actually takes.
    rendered = notifications.template_env.get_template(
        "email/unused_vehicle_warning.html"
    ).render(
        vehicle_name='<a href="https://evil/">Confirm</a>',
        vehicle_id="ABC123",
        display_name="Alice",
        _=lambda s: s,
        days_inactive=90,
        deletion_date="2026-01-01",
        server_base_url="https://example.invalid",
    )
    assert '<a href="https://evil/">' not in rendered
    assert "&lt;a href=" in rendered


# --- M-21: template routing -------------------------------------------------------

@pytest.mark.parametrize("name", [
    "email/admin_lifecycle_account.html",
    "email/admin_new_user_notification.txt",
])
def test_template_paths_are_recognised_as_files(name):
    assert notifications._is_template_file(name) is True


@pytest.mark.parametrize("subject", [
    "OVMS Security Alert: IP Blocked - 10.0.0.1",     # the regression: dots in an IPv4
    "OVMS Security Alert: IP Blocked - 192.168.1.55",
    "Vehicle ABC.1 has been inactive",
    "New User Registration: {{ new_user_username }}",
])
def test_inline_subjects_are_not_mistaken_for_template_paths(subject):
    assert notifications._is_template_file(subject) is False


def test_inline_templates_render_in_a_sandbox():
    """Defence in depth: callers interpolate DB values into these strings."""
    from jinja2.sandbox import SandboxedEnvironment

    assert isinstance(notifications._inline_template_env, SandboxedEnvironment)


def test_sandbox_blocks_attribute_escape():
    env = notifications._inline_template_env
    with pytest.raises(Exception):
        env.from_string("{{ ''.__class__.__mro__[1].__subclasses__() }}").render()


# --- H-15: SMTP certificate verification ------------------------------------------

def test_smtp_uses_an_explicit_tls_context():
    """
    Without context= both SMTP_SSL and starttls fall back to a stdlib context with
    check_hostname=False / verify_mode=CERT_NONE, and the SMTP login plus every
    reset link travels to whoever terminates the connection.
    """
    # The whole channel module, not just send_email_notification: the connection setup
    # now lives in smtp_connection() so that the socket is closed on the failure paths
    # too, and asserting over the module keeps the check from caring which of the two
    # holds it.
    from app.notifications.channels import smtp as smtp_channel

    source = inspect.getsource(smtp_channel)
    # Strip comments so the assertions below match code, not prose about the fix.
    code = "\n".join(line.split("#", 1)[0] for line in source.splitlines())
    assert "ssl.create_default_context()" in code
    assert "starttls(context=" in code
    assert "context=tls_context" in code
    # Guard against a bare call being reintroduced alongside the good one.
    assert "server.starttls()" not in code


# --- SSRF guard scheme allowlist (H-17 support) ------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/list.txt",
])
def test_outbound_guard_rejects_non_http_schemes(url):
    with pytest.raises(ValueError):
        notifications._assert_safe_outbound_url(url)


def test_outbound_guard_can_be_restricted_to_https():
    with pytest.raises(ValueError):
        notifications._assert_safe_outbound_url("http://example.com/", allowed_schemes=("https",))
