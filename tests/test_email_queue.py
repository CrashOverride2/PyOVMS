"""
The outbound e-mail queue.

SMTP used to run on whatever thread wanted to send: a FastAPI background task, an
asyncio.to_thread from the housekeeping, a daemon thread spawned per blocked IP. The
queue makes that one bounded resource, and adds three properties worth pinning down —
capacity reserved for time-critical mail, retries that outlive the old 15-second window,
and one authenticated connection carrying several messages.
"""

import threading
import types

import pytest
import smtplib

import app.notifications.email_queue as eq
from app.notifications.email_queue import EmailQueue, Priority, QueuedEmail, _PriorityDelayQueue


# ---------------------------------------------------------------------------
# the scheduling primitive, tested without threads
# ---------------------------------------------------------------------------

def _msg(subject="s", priority=Priority.NORMAL):
    return QueuedEmail(recipient="a@example.com", subject=subject, body_text="b", priority=priority)


def test_higher_priority_is_served_first():
    q = _PriorityDelayQueue(maxsize=10)
    q.put(_msg("low", Priority.LOW))
    q.put(_msg("normal", Priority.NORMAL))
    q.put(_msg("high", Priority.HIGH))

    assert [q.get(0.1).subject for _ in range(3)] == ["high", "normal", "low"]


def test_equal_priority_keeps_insertion_order():
    q = _PriorityDelayQueue(maxsize=10)
    for n in range(5):
        q.put(_msg(f"m{n}"))
    assert [q.get(0.1).subject for _ in range(5)] == [f"m{n}" for n in range(5)]


def test_a_delayed_retry_does_not_hold_up_ready_messages():
    """
    The reason there are two heaps. Keyed on due time alone, a retry scheduled for
    thirty seconds out sorts ahead of everything queued after it, and the workers sit
    and wait on it while deliverable mail piles up behind.
    """
    q = _PriorityDelayQueue(maxsize=10)
    q.put(_msg("retry-later", Priority.HIGH), delay=30)
    q.put(_msg("ready-now", Priority.LOW))

    assert q.get(0.1).subject == "ready-now"
    assert q.get(0.05) is None  # the delayed one is still not due


def test_the_queue_refuses_work_beyond_its_size():
    q = _PriorityDelayQueue(maxsize=2)
    assert q.put(_msg()) is True
    assert q.put(_msg()) is True
    assert q.put(_msg()) is False


def test_a_retry_may_exceed_the_size_limit():
    """A message already accepted must not be thrown away because the queue filled up."""
    q = _PriorityDelayQueue(maxsize=1)
    assert q.put(_msg()) is True
    assert q.put(_msg(), force=True) is True


def test_a_closed_queue_stops_accepting_and_drains():
    q = _PriorityDelayQueue(maxsize=10)
    q.put(_msg("last"))
    q.close()
    assert q.put(_msg("after-close")) is False
    assert q.get(0.1).subject == "last"
    assert q.get(0.1) is None


# ---------------------------------------------------------------------------
# the worker
# ---------------------------------------------------------------------------

class _FakeSmtp:
    """Stands in for the SMTP channel, recording connections and messages."""

    def __init__(self):
        self.connections = 0
        self.delivered = []
        self.failures = []          # exceptions to raise, one per call, None = success
        self.event = threading.Event()
        self.expected = 1

    def smtp_connection(self):
        outer = self

        class _CM:
            def __enter__(self):
                outer.connections += 1
                return types.SimpleNamespace(name="server")

            def __exit__(self, *_a):
                return False

        return _CM()

    def deliver(self, _server, recipient, subject, body_text, body_html=None):
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure
        self.delivered.append((recipient, subject))
        if len(self.delivered) >= self.expected:
            self.event.set()

    def wait(self, timeout=3.0):
        assert self.event.wait(timeout), (
            f"expected {self.expected} delivered message(s), got {len(self.delivered)}"
        )


@pytest.fixture
def smtp(monkeypatch):
    fake = _FakeSmtp()
    monkeypatch.setattr(eq.smtp_channel, "smtp_connection", fake.smtp_connection)
    monkeypatch.setattr(eq.smtp_channel, "deliver", fake.deliver)
    monkeypatch.setattr(eq.settings, "EMAIL_HOST", "smtp.example.invalid")
    monkeypatch.setattr(eq.settings, "EMAIL_SENDER", "ovms@example.invalid")
    # Retries must not make the suite wait out the real 30 s / 2 min schedule.
    monkeypatch.setattr(eq, "RETRY_DELAYS_SECONDS", (0.05, 0.05, 0.05, 0.05))
    return fake


@pytest.fixture
def queue(smtp):
    q = EmailQueue(workers=1, maxsize=50, max_attempts=5)
    yield q
    q.shutdown(drain_timeout=2.0)


def test_a_queued_message_is_delivered(queue, smtp):
    assert queue.enqueue("owner@example.com", "Hello", "body") is True

    smtp.wait()
    assert smtp.delivered == [("owner@example.com", "Hello")]
    assert queue.stats()["delivered"] == 1


def test_consecutive_messages_share_one_connection(queue, smtp):
    """The point of the queue for an admin fan-out: one handshake, not one per admin."""
    smtp.expected = 5
    for n in range(5):
        queue.enqueue(f"admin{n}@example.com", f"Report {n}", "body", priority=Priority.LOW)

    smtp.wait()
    assert len(smtp.delivered) == 5
    assert smtp.connections == 1, f"opened {smtp.connections} SMTP connections for 5 messages"


def test_a_transient_failure_is_retried_and_then_succeeds(queue, smtp):
    smtp.failures = [smtplib.SMTPConnectError(421, "try later")]
    queue.enqueue("owner@example.com", "Hello", "body")

    smtp.wait()
    assert smtp.delivered == [("owner@example.com", "Hello")]
    assert queue.stats()["failed"] == 0


def test_a_dropped_connection_reconnects_without_a_retry_delay(queue, smtp):
    """Providers close idle connections; that is not a delivery failure."""
    smtp.failures = [smtplib.SMTPServerDisconnected("closed")]
    queue.enqueue("owner@example.com", "Hello", "body")

    smtp.wait()
    assert smtp.delivered == [("owner@example.com", "Hello")]
    assert smtp.connections == 2  # the first one, then the reconnect


def test_a_permanent_failure_is_not_retried(queue, smtp):
    smtp.failures = [smtplib.SMTPRecipientsRefused({"owner@example.com": (550, b"no such user")})]
    queue.enqueue("owner@example.com", "Hello", "body")

    deadline = threading.Event()
    deadline.wait(0.5)
    assert smtp.delivered == []
    assert queue.stats()["failed"] == 1


def test_retries_are_given_up_on_eventually(queue, smtp):
    smtp.failures = [smtplib.SMTPConnectError(421, "down")] * 10
    queue.enqueue("owner@example.com", "Hello", "body")

    for _ in range(40):
        if queue.stats()["failed"]:
            break
        threading.Event().wait(0.05)

    assert queue.stats()["failed"] == 1
    assert queue.stats()["queued"] == 0


def test_shutdown_drains_what_is_already_queued(smtp):
    q = EmailQueue(workers=1, maxsize=50)
    smtp.expected = 3
    for n in range(3):
        q.enqueue(f"user{n}@example.com", "Hello", "body")
    q.shutdown(drain_timeout=3.0)

    assert len(smtp.delivered) == 3
    assert q.stats()["queued"] == 0


# ---------------------------------------------------------------------------
# admission control and validation
# ---------------------------------------------------------------------------

@pytest.fixture
def idle_queue(smtp):
    """A queue that accepts but never delivers, so the backlog can be inspected."""
    q = EmailQueue(workers=1, maxsize=10, max_attempts=5)
    q._started = True  # short-circuits start(); no worker thread is created
    return q


def test_low_priority_mail_cannot_fill_the_last_of_the_queue(idle_queue):
    limit = idle_queue.normal_priority_limit
    for n in range(limit):
        assert idle_queue.enqueue(f"a{n}@example.com", "bulk", "b", priority=Priority.LOW) is True

    assert idle_queue.enqueue("a@example.com", "more bulk", "b", priority=Priority.LOW) is False
    assert idle_queue.enqueue("a@example.com", "vehicle", "b", priority=Priority.NORMAL) is False
    # ...but the reserve is there for exactly this:
    assert idle_queue.enqueue("a@example.com", "reset link", "b", priority=Priority.HIGH) is True


def test_a_full_queue_refuses_even_high_priority(idle_queue):
    for n in range(idle_queue.maxsize):
        idle_queue.enqueue(f"a{n}@example.com", "x", "b", priority=Priority.HIGH)

    assert idle_queue.enqueue("a@example.com", "one too many", "b", priority=Priority.HIGH) is False
    assert idle_queue.stats()["rejected"] >= 1


@pytest.mark.parametrize("recipient", ["not-an-address", "", "a@b@c.example", None])
def test_a_bad_recipient_is_rejected_at_enqueue_time(idle_queue, recipient):
    """
    Synchronously, so the caller learns about it. Discovering it on a worker means the
    only record is a log line nobody asked for.
    """
    assert idle_queue.enqueue(recipient, "Hello", "body") is False
    assert idle_queue.stats()["queued"] == 0


def test_control_characters_are_stripped_from_the_subject(idle_queue):
    assert idle_queue.enqueue(
        "owner@example.com", "Alert\r\nBcc: attacker@example.com", "body"
    ) is True
    queued = idle_queue._queue.get(0.1)
    assert "\r" not in queued.subject and "\n" not in queued.subject


def test_nothing_is_queued_when_email_is_not_configured(monkeypatch, idle_queue):
    monkeypatch.setattr(eq.settings, "EMAIL_HOST", None)
    assert idle_queue.enqueue("owner@example.com", "Hello", "body") is False
    assert idle_queue.stats()["queued"] == 0


# ---------------------------------------------------------------------------
# permanence is decided by the SMTP reply code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("failure", [
    smtplib.SMTPDataError(550, b"5.7.1 message rejected as spam"),
    smtplib.SMTPDataError(552, b"message too large"),
])
def test_a_permanent_5xx_is_not_retried(queue, smtp, failure):
    """smtplib.SMTPException derives from OSError, so these once looked transient and
    burned the whole retry schedule to arrive at the answer of the first attempt."""
    smtp.failures = [failure] * 10
    queue.enqueue("owner@example.com", "Hello", "body")

    for _ in range(40):
        if queue.stats()["failed"]:
            break
        threading.Event().wait(0.05)

    assert queue.stats()["failed"] == 1
    assert queue.stats()["queued"] == 0
    assert smtp.delivered == []


def test_a_greylisting_4xx_is_retried(queue, smtp):
    """450 means "try again"; giving up would mean never reaching a greylisting server."""
    smtp.failures = [smtplib.SMTPRecipientsRefused({"owner@example.com": (450, b"greylisted")})]
    queue.enqueue("owner@example.com", "Hello", "body")

    smtp.wait()
    assert smtp.delivered == [("owner@example.com", "Hello")]


# ---------------------------------------------------------------------------
# a worker outlives an unexpected error
# ---------------------------------------------------------------------------

def test_a_worker_survives_an_unexpected_error(queue, smtp, monkeypatch):
    """There are only EMAIL_QUEUE_WORKERS workers and nothing replaces one that exits,
    so an error outside the delivery path must cost an iteration, not a worker."""
    calls = {"n": 0}
    real_process = queue._process

    def exploding_process(session, message):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("something outside the delivery path")
        return real_process(session, message)

    monkeypatch.setattr(queue, "_process", exploding_process)
    monkeypatch.setattr(eq, "WORKER_ERROR_PAUSE_SECONDS", 0.01)

    queue.enqueue("first@example.com", "Boom", "body")
    queue.enqueue("second@example.com", "Fine", "body")

    smtp.wait()
    assert smtp.delivered == [("second@example.com", "Fine")], (
        "the worker did not come back after an unexpected error"
    )


# ---------------------------------------------------------------------------
# the counters are what an operator sees
# ---------------------------------------------------------------------------

def test_stats_expose_the_admission_threshold(idle_queue):
    stats = idle_queue.stats()
    assert stats["capacity"] == idle_queue.maxsize
    assert stats["normal_priority_limit"] == idle_queue.normal_priority_limit
    assert set(stats) >= {"queued", "accepted", "delivered", "failed", "rejected"}


def test_counters_survive_concurrent_producers(idle_queue):
    """`+=` on an attribute is not indivisible; the counters are guarded."""
    def produce():
        for _ in range(50):
            idle_queue.enqueue("owner@example.com", "Hello", "body")

    threads = [threading.Thread(target=produce) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert idle_queue.stats()["accepted"] + idle_queue.stats()["rejected"] == 200
