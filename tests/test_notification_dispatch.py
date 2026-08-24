"""
Behaviour of the notification subsystem after it was split out of app/notifications.py.

The split was not a pure move — it changed four things that are worth pinning down,
because each of them was a way for one bad recipient to hurt everything else:

  * the database session is now closed before any network I/O happens, instead of being
    held for the whole fan-out (up to 20 recipients x 15 s of retry backoff);
  * recipients are sent to concurrently, so one unreachable host does not delay the
    ones behind it;
  * the rate limiter is thread-safe, monotonic and bounded;
  * retry classification is explicit, so a permanently malformed request is not tried
    three times to reach the answer it had on the first attempt.
"""

import smtplib
import threading
import types

import pytest
import requests

from app.notifications import dispatcher
from app.notifications.channels import ntfy as ntfy_channel
from app.notifications.errors import InvalidPushTargetError, TransientDeliveryError
from app.notifications.outbound import redact_url
from app.notifications.ratelimit import NotificationRateLimiter
from app.notifications.retry import (
    MAX_SEND_ATTEMPTS,
    PUSH_RETRY_DELAYS_SECONDS,
    backoff_delay,
    is_transient,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _vehicle(**overrides):
    """A Vehicle-shaped object with every flag off and no legacy targets."""
    base = {
        "id": 1,
        "vehicle_id": "CAR1",
        "protocol": "v3",
        "notification_preference": None,
        "enable_ntfy_notifications": False,
        "ntfy_topic": None,
        "ntfy_server_url": None,
        "ntfy_auth_method": None,
        "ntfy_auth_token": None,
        "ntfy_auth_user": None,
        "ntfy_auth_password": None,
        "ntfy_auth_query_param_name": None,
        "enable_email_notifications": False,
        "notification_email": None,
        "enable_fcm_notifications": False,
        "fcm_token": None,
        "enable_apns_notifications": False,
        "apns_token": None,
        "enable_unified_push_notifications": False,
        "unified_push_endpoint": None,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _subscription(sub_id, push_type, endpoint, **overrides):
    base = {
        "id": sub_id,
        "device_id": f"device-{sub_id}",
        "push_type": push_type,
        "endpoint": endpoint,
        "created_at": None,
        "ntfy_server_url": None,
        "ntfy_auth_method": None,
        "ntfy_auth_token": None,
        "ntfy_auth_user": None,
        "ntfy_auth_password": None,
        "ntfy_auth_query_param_name": None,
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


class _FakeSession:
    def __init__(self, registry):
        self.closed = False
        registry.append(self)

    def close(self):
        self.closed = True


@pytest.fixture
def dispatch_env(monkeypatch):
    """Wire the dispatcher to fakes and hand back the recorder."""
    env = types.SimpleNamespace(
        vehicle=_vehicle(),
        subscriptions=[],
        sessions=[],
        deleted=[],
        sent=[],
        senders={},
        badge_increments=0,
        scheduled_retries=[],
    )

    # Record what would have been rescheduled instead of starting a real timer thread:
    # a test that leaves one behind fails somewhere else, minutes later.
    def _capture_retry(delay, fn):
        env.scheduled_retries.append((delay, fn))
        return True

    monkeypatch.setattr(dispatcher._retry_scheduler, "schedule", _capture_retry)

    monkeypatch.setattr(dispatcher, "SessionLocal", lambda: _FakeSession(env.sessions))

    def _get_subscriptions(db, fk, limit=None):
        # The real one orders newest-first in SQL and applies the LIMIT there; the
        # dispatcher relies on both, so the fake has to honour the limit too.
        subs = list(env.subscriptions)
        return subs if limit is None else subs[:limit]

    fake_crud = types.SimpleNamespace(
        vehicle=types.SimpleNamespace(
            get_vehicle_by_vehicle_id=lambda db, vid: env.vehicle,
        ),
        push_subscription=types.SimpleNamespace(
            get_subscriptions_for_vehicle=_get_subscriptions,
            delete_subscription=lambda db, sub_id, fk: env.deleted.append((sub_id, fk)),
        ),
    )
    monkeypatch.setattr(dispatcher, "crud", fake_crud)

    import app.widget_push_service as wps

    def _increment_badge(vid):
        env.badge_increments += 1
        return 7

    monkeypatch.setattr(wps.widget_push_service, "increment_badge_count", _increment_badge)

    def _recorder(channel):
        def send(**kwargs):
            # Every send must run with no session still open, or the fan-out is once
            # again holding a pooled connection across the network.
            env.sent.append((channel, kwargs, all(s.closed for s in env.sessions)))
            behaviour = env.senders.get(channel)
            if behaviour is not None:
                return behaviour(**kwargs)
            return True
        return send

    for name, attr in (
        ("NTFY", "send_ntfy_notification"),
        ("Email", "queue_email_notification"),
        ("FCM", "send_fcm_notification"),
        ("APNs", "send_apns_notification"),
        ("UnifiedPush", "send_unified_push_notification"),
    ):
        monkeypatch.setattr(dispatcher, attr, _recorder(name))

    dispatcher.rate_limiter.reset()
    yield env
    dispatcher.rate_limiter.reset()


def _dispatch(**overrides):
    kwargs = {
        "vehicle_id": "CAR1",
        "title": "Battery low",
        "message_plain": "SOC 12%",
        "source_protocol": "v3",
    }
    kwargs.update(overrides)
    dispatcher.dispatch_notification_to_vehicle(**kwargs)


def _channels(env):
    return sorted(channel for channel, _kwargs, _closed in env.sent)


# ---------------------------------------------------------------------------
# the session is not held across the sends
# ---------------------------------------------------------------------------

def test_no_database_session_is_open_while_sending(dispatch_env):
    dispatch_env.subscriptions = [
        _subscription(1, "ntfy", "topic1"),
        _subscription(2, "email", "owner@example.com"),
        _subscription(3, "fcm", "token-abc"),
    ]

    _dispatch()

    assert _channels(dispatch_env) == ["Email", "FCM", "NTFY"]
    assert all(session_closed for _c, _k, session_closed in dispatch_env.sent), (
        "a database session was still open while an outbound request was in flight"
    )


def test_plan_carries_no_orm_objects(dispatch_env):
    """
    Closing the session early is only safe if nothing downstream can trigger a lazy
    load. The plan must therefore be plain values.
    """
    sessions = []
    db = _FakeSession(sessions)
    targets = dispatcher.build_dispatch_plan(
        db,
        _vehicle(enable_email_notifications=True, notification_email="owner@example.com"),
        icon_title="t", message_plain="m", message_html=None,
        ntfy_priority=3, ntfy_tags=None, push_data_payload={}, badge_count=1,
    )
    assert len(targets) == 1
    for value in targets[0].kwargs.values():
        assert value is None or isinstance(value, (str, int, bool, list, dict))


# ---------------------------------------------------------------------------
# one bad recipient does not take the others down
# ---------------------------------------------------------------------------

def test_a_failing_channel_does_not_stop_the_others(dispatch_env):
    dispatch_env.subscriptions = [
        _subscription(1, "ntfy", "topic1"),
        _subscription(2, "email", "owner@example.com"),
        _subscription(3, "fcm", "token-abc"),
    ]

    def boom(**_kwargs):
        raise RuntimeError("push host exploded")

    dispatch_env.senders["Email"] = boom

    _dispatch()

    assert _channels(dispatch_env) == ["Email", "FCM", "NTFY"]


def test_a_permanently_dead_target_is_unsubscribed(dispatch_env):
    dispatch_env.subscriptions = [
        _subscription(1, "ntfy", "topic1"),
        _subscription(9, "fcm", "token-dead"),
    ]

    def gone(**_kwargs):
        raise InvalidPushTargetError("token unregistered")

    dispatch_env.senders["FCM"] = gone

    _dispatch()

    assert dispatch_env.deleted == [(9, 1)], "the dead subscription was not removed"
    assert _channels(dispatch_env) == ["FCM", "NTFY"]


def test_a_dead_legacy_target_is_not_unsubscribed(dispatch_env):
    """There is no subscription row behind a vehicle-level token; nothing to delete."""
    dispatch_env.vehicle = _vehicle(enable_fcm_notifications=True, fcm_token="legacy-token")

    def gone(**_kwargs):
        raise InvalidPushTargetError("token unregistered")

    dispatch_env.senders["FCM"] = gone

    _dispatch()

    assert dispatch_env.deleted == []


# ---------------------------------------------------------------------------
# fan-out is bounded, and the vehicle-level fallback still works
# ---------------------------------------------------------------------------

def test_fan_out_is_capped(dispatch_env):
    over = dispatcher.MAX_RECIPIENTS_PER_NOTIFICATION + 5
    dispatch_env.subscriptions = [
        _subscription(i, "fcm", f"token-{i}") for i in range(over)
    ]

    _dispatch()

    assert len(dispatch_env.sent) == dispatcher.MAX_RECIPIENTS_PER_NOTIFICATION


def test_legacy_vehicle_targets_are_used_when_no_subscription_exists(dispatch_env):
    dispatch_env.vehicle = _vehicle(
        enable_ntfy_notifications=True, ntfy_topic="legacy-topic",
        enable_email_notifications=True, notification_email="owner@example.com",
    )

    _dispatch()

    assert _channels(dispatch_env) == ["Email", "NTFY"]


def test_subscriptions_win_over_the_legacy_target_on_the_same_channel(dispatch_env):
    dispatch_env.vehicle = _vehicle(enable_ntfy_notifications=True, ntfy_topic="legacy-topic")
    dispatch_env.subscriptions = [_subscription(1, "ntfy", "per-device-topic")]

    _dispatch()

    assert [k["topic"] for _c, k, _s in dispatch_env.sent] == ["per-device-topic"]


def test_protocol_preference_suppresses_the_other_source(dispatch_env):
    dispatch_env.vehicle = _vehicle(
        protocol="both", notification_preference="v2",
        enable_email_notifications=True, notification_email="owner@example.com",
    )

    _dispatch(source_protocol="v3")
    assert dispatch_env.sent == []

    dispatcher.rate_limiter.reset()
    _dispatch(source_protocol="v2")
    assert _channels(dispatch_env) == ["Email"]


# ---------------------------------------------------------------------------
# what a vehicle may push through
# ---------------------------------------------------------------------------

def test_oversized_title_and_body_are_clamped(dispatch_env):
    dispatch_env.subscriptions = [_subscription(1, "email", "owner@example.com")]

    _dispatch(title="T" * 5_000, message_plain="B" * 500_000)

    _channel, kwargs, _closed = dispatch_env.sent[0]
    # The subject also carries the alert icon and a space.
    assert len(kwargs["subject"]) <= dispatcher.MAX_TITLE_CHARS + 10
    assert len(kwargs["body_text"]) <= dispatcher.MAX_BODY_CHARS + 1


def test_rate_limit_lets_a_burst_through_then_suppresses(dispatch_env):
    """
    A single event on a module produces two or three messages (charge stopped, charge
    complete, range). The old flat interval delivered the first and discarded the rest,
    which reads to the owner as a notification arriving late — what they got was a
    *later* message, not the suppressed one.
    """
    dispatch_env.subscriptions = [_subscription(1, "email", "owner@example.com")]
    burst = dispatcher.rate_limiter.burst

    for n in range(burst + 3):
        _dispatch(title=f"msg {n}")

    assert len(dispatch_env.sent) == burst


def test_rate_limit_reports_suppression_to_the_caller(dispatch_env):
    """The MQTT subscriber uses this to release its own de-duplication slot."""
    dispatch_env.subscriptions = [_subscription(1, "email", "owner@example.com")]

    for _ in range(dispatcher.rate_limiter.burst):
        assert dispatcher.dispatch_notification_to_vehicle(
            vehicle_id="CAR1", title="t", message_plain="m", source_protocol="v3",
        ) is True

    assert dispatcher.dispatch_notification_to_vehicle(
        vehicle_id="CAR1", title="t", message_plain="m", source_protocol="v3",
    ) is False


def test_an_unknown_vehicle_does_not_reach_a_channel(dispatch_env):
    dispatch_env.vehicle = None
    dispatch_env.subscriptions = [_subscription(1, "email", "owner@example.com")]

    _dispatch()

    assert dispatch_env.sent == []
    assert all(s.closed for s in dispatch_env.sessions)


# ---------------------------------------------------------------------------
# the rate limiter itself
# ---------------------------------------------------------------------------

def test_rate_limiter_is_safe_under_concurrent_use():
    """
    The old version evicted stale keys by iterating the dict while other threads could
    insert into it, which raises RuntimeError and loses that notification.
    """
    limiter = NotificationRateLimiter(interval_seconds=0.0, max_tracked=50)
    errors = []
    allowed = []

    def hammer(offset):
        try:
            for i in range(500):
                if limiter.acquire(f"CAR{(i + offset) % 200}") is None:
                    allowed.append(1)
        except Exception as e:  # pragma: no cover - the assertion below reports it
            errors.append(e)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"rate limiter raised under concurrency: {errors}"
    assert allowed


def test_rate_limiter_table_stays_bounded():
    limiter = NotificationRateLimiter(interval_seconds=10.0, max_tracked=100)
    for i in range(1_000):
        limiter.acquire(f"CAR{i}")
    assert len(limiter._last_seen) <= 100 + 1


def test_rate_limiter_reports_the_age_of_the_previous_notification():
    limiter = NotificationRateLimiter(interval_seconds=60.0, burst=1)
    assert limiter.acquire("CAR1") is None
    assert 0.0 <= limiter.acquire("CAR1") < 60.0


def test_rate_limiter_allows_a_burst_then_holds_the_sustained_rate():
    limiter = NotificationRateLimiter(interval_seconds=60.0, burst=3)
    assert [limiter.acquire("CAR1") for _ in range(3)] == [None, None, None]
    assert limiter.acquire("CAR1") is not None


def test_rate_limiter_burst_is_per_vehicle():
    """One chatty module must not consume another vehicle's allowance."""
    limiter = NotificationRateLimiter(interval_seconds=60.0, burst=2)
    for _ in range(5):
        limiter.acquire("CAR1")
    assert limiter.acquire("CAR2") is None


def test_rate_limiter_refills_over_time():
    limiter = NotificationRateLimiter(interval_seconds=60.0, burst=2)
    for _ in range(2):
        assert limiter.acquire("CAR1") is None
    assert limiter.acquire("CAR1") is not None

    # Backdate the bucket by one interval: exactly one token is owed.
    with limiter._lock:
        tokens, stamped_at = limiter._last_seen["CAR1"]
        limiter._last_seen["CAR1"] = (tokens, stamped_at - 60.0)

    assert limiter.acquire("CAR1") is None
    assert limiter.acquire("CAR1") is not None


# ---------------------------------------------------------------------------
# retry classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    requests.exceptions.ConnectionError("refused"),
    requests.exceptions.Timeout("slow"),
    TransientDeliveryError("HTTP 503"),
    OSError("network unreachable"),
])
def test_transient_failures_are_retried(exc):
    assert is_transient(exc) is True


@pytest.mark.parametrize("exc", [
    requests.exceptions.InvalidURL("not a url"),
    requests.exceptions.MissingSchema("no scheme"),
    requests.exceptions.TooManyRedirects("loop"),
    requests.exceptions.HTTPError("400"),
])
def test_permanent_request_failures_are_not_retried(exc):
    """
    requests' exceptions derive from OSError, so the blanket OSError entry made every
    one of them retryable — three attempts and 15 s of a worker thread to reach the
    answer the first attempt already had.
    """
    assert is_transient(exc) is False


# ---------------------------------------------------------------------------
# retries are deferred, never slept through on a pooled worker
# ---------------------------------------------------------------------------

def test_no_channel_sleeps_through_its_own_retry():
    """
    The regression this guards. The push channels used to retry inline with
    time.sleep(), on a worker from a small shared pool — so one unreachable host
    removed a worker from circulation for fifteen seconds at a time and every other
    vehicle's notifications queued behind it. Waiting is the scheduler's job now.
    """
    import inspect

    from app.notifications.channels import apns, fcm, ntfy, unified_push

    for module in (ntfy, fcm, apns, unified_push):
        source = inspect.getsource(module)
        assert "time.sleep" not in source, f"{module.__name__} blocks a worker to wait"
        assert "retry_on_network_error" not in source, (
            f"{module.__name__} still retries inline instead of raising to the dispatcher"
        )


def test_the_backoff_schedule_is_bounded_and_jittered():
    for attempt, base in enumerate(PUSH_RETRY_DELAYS_SECONDS, start=1):
        delay = backoff_delay(attempt)
        assert base <= delay <= base * 1.25

    # Past the budget there is nothing left to wait for.
    assert backoff_delay(MAX_SEND_ATTEMPTS) == 0.0
    assert backoff_delay(0) == 0.0


def test_a_transient_failure_is_rescheduled_not_retried_inline(dispatch_env):
    dispatch_env.subscriptions = [_subscription(1, "fcm", "token-abc")]

    def flaky(**_kwargs):
        raise TransientDeliveryError("HTTP 503")

    dispatch_env.senders["FCM"] = flaky

    _dispatch()

    assert len(dispatch_env.sent) == 1, "the channel was called more than once inline"
    assert len(dispatch_env.scheduled_retries) == 1
    delay, _fn = dispatch_env.scheduled_retries[0]
    assert delay >= PUSH_RETRY_DELAYS_SECONDS[0]


def test_a_permanent_failure_is_not_rescheduled(dispatch_env):
    dispatch_env.subscriptions = [_subscription(1, "ntfy", "topic1")]
    dispatch_env.senders["NTFY"] = lambda **_k: (_ for _ in ()).throw(
        requests.exceptions.InvalidURL("nope")
    )

    _dispatch()

    assert dispatch_env.scheduled_retries == []


def test_an_invalid_push_target_is_not_rescheduled_but_reaped(dispatch_env):
    """A dead device is not a transient failure; retrying it three times helps nobody."""
    dispatch_env.subscriptions = [_subscription(9, "fcm", "token-dead")]
    dispatch_env.senders["FCM"] = lambda **_k: (_ for _ in ()).throw(
        InvalidPushTargetError("unregistered")
    )

    _dispatch()

    assert dispatch_env.scheduled_retries == []
    assert dispatch_env.deleted == [(9, 1)]


def test_a_rescheduled_send_reports_itself_as_pending_not_failed(dispatch_env, caplog):
    dispatch_env.subscriptions = [
        _subscription(1, "fcm", "token-abc"),
        _subscription(2, "email", "owner@example.com"),
    ]
    dispatch_env.senders["FCM"] = lambda **_k: (_ for _ in ()).throw(
        TransientDeliveryError("HTTP 503")
    )

    with caplog.at_level("WARNING"):
        _dispatch()

    assert any("retrying FCM" in record.message for record in caplog.records), (
        "a send that is booked for another attempt was reported as a hard failure"
    )


# ---------------------------------------------------------------------------
# NTFY topic validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("topic", [
    "../../v1/account/settings",   # escapes the topic path, taking the bearer token
    "topic?auth=steal",            # smuggles a query string
    "topic with spaces",
    # Excluding '/' bounds a dot segment to one level, but '..' still addresses the
    # server root rather than a topic — and a name made only of punctuation is not a
    # topic anyone meant.
    "..",
    ".",
    "...",
    "_",
    "-",
    # Longer than Vehicle.ntfy_topic can hold, so nothing that was ever stored here.
    # The bound deliberately does not track NTFY's own 64 — see _TOPIC_RE.
    "a" * 101,
    "",
])
def test_hostile_ntfy_topics_are_refused(topic, monkeypatch):
    def must_not_be_called(*_a, **_k):  # pragma: no cover - the assertion is the point
        raise AssertionError(f"a request was made for topic {topic!r}")

    monkeypatch.setattr(ntfy_channel, "post", must_not_be_called)
    assert ntfy_channel.send_ntfy_notification(topic, "Title", "body") is False


@pytest.mark.parametrize("topic", ["ovms_alerts", "CAR-1.status", "/leading-slash/", "_leading_underscore"])
def test_ordinary_ntfy_topics_are_accepted(topic, monkeypatch):
    seen = {}

    def fake_post(url, **kwargs):
        seen["url"] = url
        return 200, ""

    monkeypatch.setattr(ntfy_channel, "post", fake_post)
    assert ntfy_channel.send_ntfy_notification(topic, "Title", "body", server_url="https://ntfy.example") is True
    assert seen["url"].startswith("https://ntfy.example/")


@pytest.mark.parametrize("status", [429, 500, 503])
def test_ntfy_rate_limiting_is_treated_as_transient(monkeypatch, status):
    """A 429 from a public NTFY instance used to lose the message outright.

    The channel raises rather than retrying: it is called on a pooled worker, and the
    dispatcher — which knows about the scheduler — decides what waiting costs.
    """
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return status, "try later"

    monkeypatch.setattr(ntfy_channel, "post", fake_post)

    with pytest.raises(TransientDeliveryError):
        ntfy_channel.send_ntfy_notification(
            "ovms_alerts", "Title", "body", server_url="https://ntfy.example"
        )
    assert len(calls) == 1, "the channel retried inline instead of raising"
    assert is_transient(TransientDeliveryError("x")) is True


# ---------------------------------------------------------------------------
# the badge is a side effect, so only a channel that carries one may trigger it
# ---------------------------------------------------------------------------

def test_the_badge_is_not_incremented_without_a_badge_carrying_target(dispatch_env):
    """A vehicle with no push device must not accumulate a badge nothing can clear."""
    dispatch_env.subscriptions = [_subscription(1, "email", "owner@example.com")]

    _dispatch()

    assert dispatch_env.badge_increments == 0


def test_the_badge_is_incremented_once_for_several_badge_targets(dispatch_env):
    dispatch_env.subscriptions = [
        _subscription(1, "apns", "token-a"),
        _subscription(2, "apns", "token-b"),
        _subscription(3, "up", "https://push.example/x"),
    ]

    _dispatch()

    assert dispatch_env.badge_increments == 1
    assert {k["badge"] for _c, k, _s in dispatch_env.sent} == {7}


# ---------------------------------------------------------------------------
# a channel that returns False is a failure, not a delivery
# ---------------------------------------------------------------------------

def test_a_channel_that_declines_is_reported(dispatch_env, caplog):
    dispatch_env.subscriptions = [
        _subscription(1, "ntfy", "topic1"),
        _subscription(2, "email", "owner@example.com"),
    ]
    dispatch_env.senders["Email"] = lambda **_kwargs: False

    with caplog.at_level("WARNING"):
        _dispatch()

    assert any("1/2 target(s) accepted" in record.message for record in caplog.records), (
        "a channel that refused the message was counted as delivered"
    )


# ---------------------------------------------------------------------------
# SMTP failures are classified by reply code, not by exception class
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("exc", [
    smtplib.SMTPDataError(550, b"5.7.1 message rejected as spam"),
    smtplib.SMTPDataError(552, b"message too large"),
    smtplib.SMTPSenderRefused(553, b"sender not allowed", "x@y.z"),
    smtplib.SMTPRecipientsRefused({"a@b.c": (550, b"no such user")}),
])
def test_permanent_smtp_failures_are_not_retried(exc):
    """smtplib.SMTPException derives from OSError, which used to make all of these
    look transient and cost the full ~40 minute retry schedule per recipient."""
    assert is_transient(exc) is False


@pytest.mark.parametrize("exc", [
    smtplib.SMTPConnectError(421, "service not available, try later"),
    # Greylisting. Giving up here would mean never delivering to a greylisting server.
    smtplib.SMTPRecipientsRefused({"a@b.c": (450, b"greylisted, try again")}),
])
def test_temporary_smtp_failures_are_still_retried(exc):
    assert is_transient(exc) is True


# ---------------------------------------------------------------------------
# credentials do not reach the log
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://ntfy.example/topic?token=tk_secret", "https://ntfy.example/topic?[redacted]"),
    ("https://user:pw@ntfy.example/topic", "https://ntfy.example/topic"),
    ("https://ntfy.example/topic", "https://ntfy.example/topic"),
])
def test_urls_are_redacted_before_logging(url, expected):
    """NTFY's query auth mode puts the owner's token in the URL."""
    assert redact_url(url) == expected
