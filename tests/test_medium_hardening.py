"""
Remaining MEDIUM findings from the 2026-08-01 audit.

Grouped in one module because they share a shape: each is a place where data that
arrives from a vehicle — a metric value, a clock, a topic segment — was trusted a
little too far, or where a failure path gave up on something that must not be given
up on.

  M-3   The broker sync dropped a job after three failures. For a revocation that
        meant the deleted module kept its broker login until someone restarted.
  M-7   The V2 handshake wrote to the DB before checking the HMAC, which both timed
        the answer to "does this vehicle id exist" and let an unauthenticated peer
        reset the inactivity clock that drives auto-deletion.
  M-8   last_seen_v3 came from a vehicle-published metric with no sanity check, so
        `m.time.utc = 9999-01-01` pinned a car "online" forever.
  M-9   float("inf") parses fine and int() of it raises, so one metric could turn
        the state endpoint into a 500 for as long as the value stayed cached.
  M-11  Notification dispatch ran on the single paho network thread.
  M-22  The installer's secret generator looked for the template in the wrong
        directory and silently produced a partial .env.
  M-23  The SQLite file was created world-readable.
  H-11  The notification de-duplication caches never evicted anything.
"""

import inspect
import os
import stat
import time
from pathlib import Path

import pytest

from app.mqtt_notification_subscriber import MqttNotificationSubscriber
from app.protocols.v2 import auth as v2_auth
from app.services import mqtt_sync_worker as worker_module
from app.utils.parsing_helpers import _safe_float_parse, _safe_truncated_int_str

REPO_ROOT = Path(__file__).resolve().parent.parent


def _code_only(obj):
    lines = inspect.getsource(obj).splitlines()
    return "\n".join(line for line in lines if not line.strip().startswith("#"))


# ---------------------------------------------------------------------------
# M-9 — non-finite numbers must not reach int()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", ["inf", "-inf", "Infinity", "nan", "NaN", "1e400"])
def test_non_finite_values_are_rejected(payload):
    """float() parses all of these; the `is not None` guard did not catch them."""
    assert _safe_float_parse(payload) is None


@pytest.mark.parametrize("payload", ["inf", "-inf", "nan", "1e400"])
def test_odometer_conversion_survives_non_finite(payload):
    """
    The actual crash: `int(float("inf"))` raises OverflowError, and the V3 merge
    block had no try/except, so GET /vehicle_state returned 500 until the metric
    expired — refreshable at will by republishing.
    """
    assert _safe_truncated_int_str(payload) == "0"


@pytest.mark.parametrize("payload,expected", [("123.7", "123"), ("-4.9", "-4"), ("0", "0")])
def test_ordinary_values_still_convert(payload, expected):
    assert _safe_truncated_int_str(payload) == expected


def test_finite_values_still_parse():
    assert _safe_float_parse("12.5") == 12.5
    assert _safe_float_parse("") is None
    assert _safe_float_parse(None) is None


def test_v3_merge_block_isolates_a_bad_metric():
    """
    Belt and braces: even if a converter raises for some other reason, one metric
    must not take down the whole response.
    """
    from app.utils import vehicle_state_parser

    source = _code_only(vehicle_state_parser.parse_vehicle_state_to_json)
    loop = source[source.index("for v3_key, (v2_key, converter, fmt)"):]

    assert "try:" in loop
    assert "except Exception" in loop


# ---------------------------------------------------------------------------
# M-8 — the vehicle's clock is not authoritative
# ---------------------------------------------------------------------------


def test_clock_skew_limit_is_defined_and_tight():
    from app.mqtt_metrics_subscriber import MqttMetricsSubscriber

    assert 0 < MqttMetricsSubscriber.MAX_VEHICLE_CLOCK_SKEW_SECONDS <= 3600


def test_implausible_vehicle_timestamp_is_replaced_by_server_time():
    """
    `m.time.utc = 9999-01-01` used to become last_seen_v3 directly: the car counted
    as online forever, connection-loss alerts never fired, and the write throttle —
    which compared against that same future value — suppressed every later update.

    The check now lives in _resolve_timestamp(); what _on_message still has to get
    right is calling it before the timestamp goes anywhere. The behaviour of the
    resolver itself is covered in tests/test_vehicle_clock.py.
    """
    from app.mqtt_metrics_subscriber import MqttMetricsSubscriber

    resolver = _code_only(MqttMetricsSubscriber._resolve_timestamp)
    assert "MAX_VEHICLE_CLOCK_SKEW_SECONDS" in resolver

    source = _code_only(MqttMetricsSubscriber._on_message)

    resolve_call = source.index("_resolve_timestamp")
    charge_call = source.index("charge_manager.process_metric")
    assert resolve_call < charge_call, (
        "the timestamp reaches the charge manager before it is validated"
    )


def test_write_throttle_uses_a_clock_the_vehicle_cannot_move():
    """
    A future timestamp in the throttle comparison would hold it open indefinitely,
    so the throttle must run on monotonic time, not on the payload timestamp.
    """
    from app.mqtt_metrics_subscriber import MqttMetricsSubscriber

    source = _code_only(MqttMetricsSubscriber._on_message)
    throttle = source[source.index("last_write_at = "):]

    assert "time.monotonic()" in throttle[:400]


# ---------------------------------------------------------------------------
# M-7 — nothing is written before the digest matches
# ---------------------------------------------------------------------------


def test_v2_handshake_writes_only_after_the_digest_check():
    source = _code_only(v2_auth.handle_authentication)

    compare = source.index("hmac.compare_digest")
    write = source.index("update_vehicle_last_seen_tcp")

    assert compare < write, (
        "the V2 handshake still writes to the DB before authenticating — a timing "
        "oracle for vehicle ids and a way to reset the auto-deletion clock"
    )


# ---------------------------------------------------------------------------
# M-3 — a revocation is never abandoned
# ---------------------------------------------------------------------------


def test_failed_jobs_are_always_requeued():
    """
    Drives the real claim/fail/requeue cycle rather than calling _requeue in a loop.

    Without the _claim() in between, the job stays in _pending from an earlier
    iteration and the assertion passes even when the worker has stopped re-adding it
    — this test did exactly that at first and waved the old drop-after-3 behaviour
    straight through.
    """
    worker = worker_module.MqttSyncWorker()
    job = ("vehicle", "GONECAR")
    worker._pending.add(job)

    for cycle in range(worker_module.MAX_ATTEMPTS + 5):
        worker._retry_at.clear()  # don't sit out the backoff in a test
        claimed = worker._claim()
        assert job in claimed, (
            f"the sync worker stopped retrying after {cycle} attempts; for a "
            f"revocation that leaves the deleted module authenticating against the "
            f"broker until someone restarts the process"
        )
        worker._requeue(claimed)

    assert job in worker._pending


def test_backoff_grows_and_is_capped():
    worker = worker_module.MqttSyncWorker()
    job = ("vehicle", "SLOWCAR")

    delays = []
    for _ in range(12):
        before = time.monotonic()
        worker._requeue({job})
        delays.append(worker._retry_at[job] - before)

    assert delays[1] > delays[0], "backoff does not grow"
    assert max(delays) <= worker_module.MAX_RETRY_DELAY_SECONDS + 1, "backoff is uncapped"


def test_backoff_is_per_job_not_global():
    """One permanently failing job used to hold back every unrelated one."""
    worker = worker_module.MqttSyncWorker()
    stuck, fresh = ("vehicle", "STUCK"), ("acl", "")

    for _ in range(5):
        worker._requeue({stuck})
    worker._pending.add(fresh)

    claimed = worker._claim()

    assert fresh in claimed, "an unrelated job was delayed by another job's backoff"
    assert stuck not in claimed, "the backed-off job was claimed too early"


def test_security_event_fires_once_not_every_cycle():
    """
    Jobs are no longer dropped at MAX_ATTEMPTS, so reporting on every cycle would
    bury the log it exists to draw attention to.
    """
    source = _code_only(worker_module.MqttSyncWorker._report_failures)

    assert "== MAX_ATTEMPTS" in source, (
        "failure reporting is not edge-triggered on the threshold"
    )


# ---------------------------------------------------------------------------
# M-11 — the paho thread must not do network I/O for notifications
# ---------------------------------------------------------------------------


def test_dispatch_is_offloaded_from_the_mqtt_callback():
    source = _code_only(MqttNotificationSubscriber._on_message)

    assert "_dispatch_pool.submit" in source
    assert "notifications.dispatch_notification_to_vehicle(" not in source, (
        "notification dispatch still runs inline on the paho network thread"
    )


def test_dispatch_pool_is_bounded():
    """Both stages behind the MQTT network thread are bounded in workers *and* in queue.

    The worker count was always bounded; the queue was not. A ThreadPoolExecutor accepts
    an unlimited backlog, so when the workers fell behind the queue simply grew and every
    notification in it went out later than the one before, with nothing in the log to say
    it was happening.
    """
    from app.utils.bounded_worker import BoundedWorkerPool

    sub = MqttNotificationSubscriber()
    for pool in (sub._dispatch_pool, sub._data_pool):
        assert isinstance(pool, BoundedWorkerPool)
        assert 0 < pool.workers <= 64
        assert 0 < pool.maxsize < 1_000_000


def test_history_records_do_not_run_on_the_mqtt_network_thread():
    """
    paho calls on_message synchronously on its single network thread, so anything done
    inline there stops the socket being read. Storing a history record is a session,
    several queries and a commit — per record — and the push notification arriving
    behind a reconnecting module's buffer flush waited for all of them.
    """
    source = _code_only(MqttNotificationSubscriber._on_message)
    data_branch = source[source.index("if notification_type == 'data':"):]

    for handler in ("_handle_v3_data_record", "_handle_v3_debug_data", "_handle_v3_crash_log"):
        assert f"self.{handler}(" not in data_branch, (
            f"{handler} is called inline on the MQTT network thread"
        )
        assert handler in data_branch, f"{handler} is no longer reachable"
    assert "_data_pool.submit" in data_branch


def test_worker_failures_are_logged_not_swallowed():
    source = _code_only(MqttNotificationSubscriber._dispatch_safely)

    assert "except Exception" in source
    assert "logger.error" in source


# ---------------------------------------------------------------------------
# H-11 — the de-duplication caches are bounded
# ---------------------------------------------------------------------------


def test_stale_cache_entries_are_pruned():
    sub = MqttNotificationSubscriber()
    now = time.time()
    old = now - (MqttNotificationSubscriber.SIMILAR_NOTIFICATION_WINDOW_SECONDS + 5)

    sub._last_notification_type_cache["CAR1:info/old"] = (old, "info/old")
    sub._last_notification_type_cache["CAR1:info/new"] = (now, "info/new")

    sub._prune_caches(now)

    assert "CAR1:info/old" not in sub._last_notification_type_cache
    assert "CAR1:info/new" in sub._last_notification_type_cache


def test_cache_is_capped_against_a_burst_inside_one_window():
    """Entries inside the window are all live, so only a hard cap bounds a burst."""
    sub = MqttNotificationSubscriber()
    now = time.time()

    for i in range(MqttNotificationSubscriber.MAX_CACHE_ENTRIES + 100):
        sub._last_notification_type_cache[f"CAR1:info/{i}"] = (now, f"info/{i}")

    sub._prune_caches(now)

    assert len(sub._last_notification_type_cache) <= MqttNotificationSubscriber.MAX_CACHE_ENTRIES


def test_pruning_runs_before_the_cache_is_written():
    source = _code_only(MqttNotificationSubscriber._on_message)

    prune = source.index("_prune_caches(")
    write = source.index("self._last_notification_cache[vehicle_id] =")

    assert prune < write


# ---------------------------------------------------------------------------
# M-22 / M-23 — installer and on-disk permissions
# ---------------------------------------------------------------------------


def test_secret_generator_finds_the_real_template():
    """
    It looked in doc/security/, where no template has ever existed, so the minimal
    fallback branch always ran — omitting SECRET_KEY_SESSION and the MQTT file
    paths, which left install.sh's sed a no-op and the broker sync silently off.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_secrets", REPO_ROOT / "doc" / "security" / "generate_secrets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    template = module.read_env_template()

    assert template, "template still not found"
    for key in ("SECRET_KEY_SESSION", "MQTT_PASSWD_FILE", "MQTT_ACL_FILE"):
        assert key in template, f"{key} missing from the template that gets used"


def test_generated_env_is_owner_only(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_secrets", REPO_ROOT / "doc" / "security" / "generate_secrets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    target = tmp_path / "generated.env"
    content = module.generate_env_content()
    target.write_text(content)
    os.chmod(target, 0o600)

    assert stat.S_IMODE(target.stat().st_mode) & 0o077 == 0

    # And the content is the full template, not the stub.
    assert "SECRET_KEY_SESSION" in content
    assert "MQTT_PASSWD_FILE" in content


def test_generated_env_contains_no_placeholder_secrets():
    """
    The generator matched whole `KEY=placeholder` literals, but every assignment in
    .env-template is double-quoted — so all six str.replace() calls matched nothing and
    it wrote a .env with every secret still at its placeholder, while printing
    "Secure secrets generated". The two tests above passed throughout: they only checked
    that the keys were *present*, never that the values had changed.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_secrets", REPO_ROOT / "doc" / "security" / "generate_secrets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    content = module.generate_env_content()

    # Same markers run.py treats as "never customised".
    from app.secret_initializer import _DEFAULT_MARKERS, _SECRET_KEYS, _parse_env_file

    values = _parse_env_file(content)
    for key in _SECRET_KEYS:
        value = values.get(key, "")
        assert value.strip(), f"{key} is empty in the generated .env"
        for marker in _DEFAULT_MARKERS:
            assert marker not in value, f"{key} is still a placeholder: {marker!r}"


def test_generated_env_jwt_pair_survives_the_startup_guard():
    """
    A .env from this script must be usable as-is, with no write access at runtime — a
    container mounts it read-only and cannot let run.py patch it. bootstrap aborts on an
    unusable key and on a pair whose halves do not match, so check both here.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generate_secrets", REPO_ROOT / "doc" / "security" / "generate_secrets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from app.secret_initializer import _parse_env_file

    values = _parse_env_file(module.generate_env_content())

    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # app/jwt_keys._decode_b64 uses validate=True and requires exactly 32 raw bytes.
    private_raw = base64.b64decode(values["JWT_PRIVATE_KEY"], validate=True)
    public_raw = base64.b64decode(values["JWT_PUBLIC_KEY"], validate=True)
    assert len(private_raw) == 32
    assert len(public_raw) == 32

    derived = Ed25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert derived == public_raw, "mismatched pair — every login would fail"


def test_generator_chmods_what_it_writes():
    source = (REPO_ROOT / "doc" / "security" / "generate_secrets.py").read_text()

    assert "os.chmod(output_path, 0o600)" in source


def test_sqlite_file_permissions_are_tightened(tmp_path):
    from app.database import _restrict_sqlite_permissions

    db_file = tmp_path / "ovms.db"
    db_file.write_bytes(b"")
    os.chmod(db_file, 0o644)

    _restrict_sqlite_permissions(db_file)

    assert stat.S_IMODE(db_file.stat().st_mode) & 0o077 == 0


def test_sqlite_hardening_ignores_other_backends():
    from app.database import _sqlite_path

    assert _sqlite_path("postgresql://user@host/db") is None
    assert _sqlite_path("sqlite:///:memory:") is None
    assert _sqlite_path("sqlite:///./ovms_py.db") == Path("./ovms_py.db")


def test_systemd_unit_is_sandboxed():
    install_sh = (REPO_ROOT / "install.sh").read_text()

    for directive in (
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=",
        "ReadWritePaths=",
    ):
        assert directive in install_sh, f"systemd unit is missing {directive}"


# ---------------------------------------------------------------------------
# M-20 — the middleware stack matches its documented order
# ---------------------------------------------------------------------------


EXPECTED_MIDDLEWARE_ORDER = [
    "SecurityHeadersMiddleware",
    "RemoveServerHeaderMiddleware",
    # Inside the header middlewares, because its own 400 for a bad Host is a
    # short-circuit response and has to carry the same headers as any other.
    "TrustedHostMiddleware",
    "CORSMiddleware",
    "SecurityMiddleware",
    "SessionMiddleware",
    "BabelMiddleware",
]


def test_middleware_order_is_outermost_first():
    """
    Starlette prepends, so the last registration is the outermost layer.
    """
    from app.main import app

    actual = [m.cls.__name__ for m in app.user_middleware]
    assert actual == EXPECTED_MIDDLEWARE_ORDER, (
        f"middleware stack is {actual}, expected {EXPECTED_MIDDLEWARE_ORDER}"
    )


def test_security_headers_wrap_the_ip_block_response():
    """
    The consequence that made the ordering a security issue, asserted over real HTTP:
    SecurityMiddleware answers a blocked IP itself, so the header middleware has to
    sit *outside* it or that 429 goes out bare.
    """
    from fastapi.testclient import TestClient

    from app.main import app
    from app.security_manager import security_manager

    security_manager.blocked_ips.clear()
    security_manager.blocked_ips["testclient"] = time.time() + 3600
    try:
        with TestClient(app) as client:
            response = client.get("/login")
    finally:
        security_manager.blocked_ips.clear()

    assert response.status_code == 429, "expected the IP block to short-circuit"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in response.headers
    assert "server" not in {k.lower() for k in response.headers}


# ---------------------------------------------------------------------------
# M-10 — charge sessions cannot be created by flapping a metric
# ---------------------------------------------------------------------------


def test_charge_session_limits_are_defined():
    from app.services.charge_logger.charge_manager import ChargeManager

    assert ChargeManager.MIN_SESSION_DURATION_SECONDS >= 30
    assert ChargeManager.MIN_SESSION_GAP_SECONDS > 0


def test_short_sessions_are_discarded_again():
    """
    A flip of v.c.charging used to persist a ChargeLog plus points unconditionally,
    so alternating yes/no grew the table without bound.
    """
    from app.services.charge_logger.charge_manager import ChargeManager

    source = _code_only(ChargeManager._end_charge_session)

    assert "MIN_SESSION_DURATION_SECONDS" in source
    assert "delete_charge_log" in source


def test_new_sessions_are_rate_limited_after_one_closes():
    from app.services.charge_logger.charge_manager import ChargeManager

    source = _code_only(ChargeManager.process_metric)

    assert "MIN_SESSION_GAP_SECONDS" in source
    gap = source.index("MIN_SESSION_GAP_SECONDS")
    start = source.index("_start_charge_session")
    assert gap < start, "the gap check runs after the session is already created"


# ---------------------------------------------------------------------------
# M-17 — the grab bag
# ---------------------------------------------------------------------------


def test_info_box_renderer_exists_once():
    """
    Both dashboards render the same operator-authored Markdown. They had separate
    copies and the copies had drifted: the admin one stripped `javascript:` hrefs,
    the user one — serving everyone else — did not.
    """
    from app.routers.ui import admin, dashboard
    from app.utils.safe_markdown import render_safe_markdown

    assert admin._render_safe_markdown is render_safe_markdown
    assert dashboard._render_safe_markdown is render_safe_markdown


@pytest.mark.parametrize("scheme", ["javascript", "data", "vbscript", "JavaScript"])
def test_dangerous_uri_schemes_are_stripped(scheme):
    from app.utils.safe_markdown import render_safe_markdown

    rendered = render_safe_markdown(f"[click]({scheme}:alert(1))")

    assert f"{scheme}:" not in rendered
    assert 'href="#"' in rendered


def test_raw_html_in_the_info_box_is_escaped():
    from app.utils.safe_markdown import render_safe_markdown

    rendered = render_safe_markdown("<script>alert(1)</script>")

    assert "<script>" not in rendered


def test_ordinary_links_still_render():
    from app.utils.safe_markdown import render_safe_markdown

    rendered = render_safe_markdown("[docs](https://example.com/x)")

    assert 'href="https://example.com/x"' in rendered


def test_ntfy_headers_are_sanitised():
    """
    The title comes from vehicle-supplied notification text and the tags from the
    topic. The e-mail path already used sanitize_header_value; this one did not, so
    a CR/LF could append headers to the request carrying the user's NTFY token.
    """
    from app import notifications

    source = _code_only(notifications.send_ntfy_notification)
    header_block = source[source.index("headers = {"):]

    assert "sanitize_header_value(encoded_title_for_header)" in header_block
    assert "sanitize_header_value(t)" in header_block


def test_vehicle_password_has_a_real_minimum():
    """It is the V2 HMAC key and the broker password; min_length=1 was brute-forceable."""
    from app.models import api as models_api

    assert models_api.MIN_VEHICLE_PASSWORD_LENGTH >= 12

    with pytest.raises(Exception):
        models_api.VehicleCreate(vehicle_id="CAR1", server_password="x")

    ok = models_api.VehicleCreate(vehicle_id="CAR1", server_password="a" * 16)
    assert ok.server_password == "a" * 16


def test_tls_listener_sets_a_minimum_version():
    from app import tcp_server

    source = _code_only(tcp_server.start_tcp_server_main)

    assert "minimum_version" in source
    assert "TLSv1_2" in source
    assert "set_ciphers" in source


def test_changing_the_second_factor_invalidates_other_sessions():
    """
    Enabling or disabling 2FA is what someone does when they think another session is
    not theirs. Without a token_version bump there was no way to end those sessions.
    """
    from app.crud import user as crud_user

    for fn in (crud_user.enable_totp_for_user, crud_user.disable_totp_for_user):
        assert "token_version" in _code_only(fn), (
            f"{fn.__name__} does not invalidate existing sessions"
        )


def test_the_acting_session_survives_a_2fa_change():
    """
    ...but the user must not be logged out by their own security action, or the
    feature reads as broken and people stop using it. The same goes for a password
    change on the profile page: update_user() bumps token_version there too, and
    without the re-issue the redirect to the success message was the login page.
    """
    from app.routers.ui import profile

    for fn in (
        profile.ui_totp_enable_submit_route,
        profile.ui_totp_disable_submit_route,
        profile.ui_change_password_submit_route,
    ):
        assert "_reissue_session_cookie" in _code_only(fn), (
            f"{fn.__name__} bumps token_version without re-issuing the caller's cookie"
        )


def test_notification_fan_out_is_capped():
    """
    The rate limit is keyed on vehicle_id alone, so one permitted notification used
    to fan out to however many subscriptions existed — each an outbound request.
    """
    from app import notifications

    assert 0 < notifications.MAX_RECIPIENTS_PER_NOTIFICATION <= 100

    # The recipient lists are built in build_dispatch_plan(); dispatch_notification_to_vehicle
    # now only rate-limits, plans, and executes.
    source = _code_only(notifications.build_dispatch_plan)
    assert "MAX_RECIPIENTS_PER_NOTIFICATION" in source

    cap = source.index("MAX_RECIPIENTS_PER_NOTIFICATION")
    first_send = source.index("ntfy_subs = ")
    assert cap < first_send, "the cap is applied after the recipient lists are built"
