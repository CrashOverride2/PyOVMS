"""An outbound e-mail queue.

SMTP is by a wide margin the slowest thing this server does: a connection, a TLS
handshake, an AUTH round trip and then the message, against a host nobody here controls.
Every caller used to pay that latency on its own thread — a FastAPI background task
during registration, an `asyncio.to_thread` during the nightly housekeeping, a freshly
spawned daemon thread per blocked IP in the security manager, and the notification
fan-out for every e-mail recipient of every vehicle.

"""

import heapq
import itertools
import logging
import random
import smtplib
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Tuple

from app.config import settings
from app.notifications.channels import smtp as smtp_channel
from app.notifications.retry import is_transient
from app.utils.email_validation import (
    InvalidEmailAddress,
    sanitize_header_value,
    validate_email_address,
)

logger = logging.getLogger(__name__)


class Priority(IntEnum):
    """Lower value is served first."""

    HIGH = 0    # someone is sitting in front of a browser waiting: reset, verification
    NORMAL = 1  # vehicle notifications
    LOW = 2     # admin fan-out, lifecycle reports — nobody is waiting on these


# Backoff between attempts, in seconds. Deliberately long compared with the 5/10 s of the
# inline retry: the failure this is for is "the mail server is down for a few minutes",
# and nothing is holding a thread while we wait.
RETRY_DELAYS_SECONDS = (30, 120, 480, 1800)

# Close a connection that has been idle this long. Providers drop idle connections
# themselves; doing it first keeps the reconnect off the critical path of a message.
IDLE_CONNECTION_SECONDS = 30.0

# Recycle the connection periodically even under load — several providers cap the number
# of messages per session and answer the next one with an error that looks transient.
MAX_MESSAGES_PER_CONNECTION = 50

# A worker that hits an error outside the delivery path (which has its own handling)
# keeps going: there are only EMAIL_QUEUE_WORKERS of them and nothing replaces one that
# exits. It gives up only if it cannot make progress at all, so a genuinely broken
# worker does not spin on the same failure forever.
MAX_CONSECUTIVE_WORKER_ERRORS = 10
WORKER_ERROR_PAUSE_SECONDS = 1.0


@dataclass
class QueuedEmail:
    recipient: str
    subject: str
    body_text: str
    body_html: Optional[str] = None
    priority: Priority = Priority.NORMAL
    attempts: int = 0

    def describe(self) -> str:
        return f"'{self.subject[:60]}' → {self.recipient}"


class _PriorityDelayQueue:
    """A priority queue whose items can be scheduled into the future.

    Two heaps rather than one keyed on (due_at, priority): with a single heap a retry
    scheduled for thirty seconds from now sorts ahead of everything queued later, so the
    workers would sit and wait on it while ready messages piled up behind it.
    """

    def __init__(self, maxsize: int):
        self._maxsize = maxsize
        self._ready: List[Tuple[int, int, QueuedEmail]] = []          # (priority, seq, item)
        self._delayed: List[Tuple[float, int, QueuedEmail]] = []      # (due_at, seq, item)
        self._seq = itertools.count()
        self._cv = threading.Condition()
        self._closed = False

    def put(self, item: QueuedEmail, delay: float = 0.0, *, force: bool = False) -> bool:
        """Enqueue. Returns False when the queue is closed or over its limit."""
        with self._cv:
            if self._closed:
                return False
            if not force and self._size_locked() >= self._maxsize:
                return False
            seq = next(self._seq)
            if delay > 0:
                heapq.heappush(self._delayed, (time.monotonic() + delay, seq, item))
            else:
                heapq.heappush(self._ready, (int(item.priority), seq, item))
            self._cv.notify()
            return True

    def get(self, timeout: float) -> Optional[QueuedEmail]:
        """Next due item, or None on timeout / when closed and drained."""
        deadline = time.monotonic() + timeout
        with self._cv:
            while True:
                self._promote_locked()
                if self._ready:
                    return heapq.heappop(self._ready)[2]
                if self._closed and not self._delayed:
                    return None
                now = time.monotonic()
                wait = deadline - now
                if self._delayed:
                    wait = min(wait, self._delayed[0][0] - now)
                if wait <= 0:
                    return None
                self._cv.wait(wait)

    def _promote_locked(self) -> None:
        now = time.monotonic()
        while self._delayed and self._delayed[0][0] <= now:
            _due, seq, item = heapq.heappop(self._delayed)
            heapq.heappush(self._ready, (int(item.priority), seq, item))

    def _size_locked(self) -> int:
        return len(self._ready) + len(self._delayed)

    def size(self) -> int:
        with self._cv:
            return self._size_locked()

    def close(self) -> Tuple[int, int]:
        """Stop accepting. Returns (ready, delayed) counts still held."""
        with self._cv:
            self._closed = True
            self._cv.notify_all()
            return len(self._ready), len(self._delayed)

    def wake_all(self) -> None:
        with self._cv:
            self._cv.notify_all()


class _SmtpSession:
    """A lazily-opened SMTP connection, reused across consecutive messages."""

    def __init__(self):
        self._cm = None
        self._server = None
        self._sent = 0
        self._opened_at = 0.0

    def server(self):
        if self._server is None:
            self._cm = smtp_channel.smtp_connection()
            self._server = self._cm.__enter__()
            self._sent = 0
            self._opened_at = time.monotonic()
            logger.debug("Email queue: opened SMTP connection to %s.", settings.EMAIL_HOST)
        return self._server

    def note_sent(self) -> None:
        self._sent += 1

    @property
    def exhausted(self) -> bool:
        return self._server is not None and self._sent >= MAX_MESSAGES_PER_CONNECTION

    @property
    def is_open(self) -> bool:
        return self._server is not None

    def close(self) -> None:
        if self._cm is not None:
            try:
                self._cm.__exit__(None, None, None)
            except Exception:
                pass
        self._cm = None
        self._server = None


class EmailQueue:
    """Bounded, prioritised, retrying delivery of outbound mail."""

    def __init__(self, workers: int = None, maxsize: int = None, max_attempts: int = None):
        self.workers = workers if workers is not None else settings.EMAIL_QUEUE_WORKERS
        self.maxsize = maxsize if maxsize is not None else settings.EMAIL_QUEUE_MAX_SIZE
        self.max_attempts = max_attempts if max_attempts is not None else settings.EMAIL_QUEUE_MAX_ATTEMPTS

        # Capacity below this mark is reserved for HIGH priority. Without it a vehicle
        # publishing notifications in a loop fills the queue and the password-reset mail
        # behind it is the one that gets refused.
        self.normal_priority_limit = max(1, int(self.maxsize * 0.8))

        self._queue = _PriorityDelayQueue(self.maxsize)
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._started = False

        # Counted from both the producers (any request thread) and the workers, so the
        # increments are guarded rather than relying on `+=` being indivisible — which
        # it is not, and which the free-threaded builds no longer paper over.
        self._counts = {"accepted": 0, "delivered": 0, "failed": 0, "rejected": 0}
        self._counts_lock = threading.Lock()

    def _bump(self, key: str) -> None:
        with self._counts_lock:
            self._counts[key] += 1

    @property
    def accepted(self) -> int:
        return self._counts["accepted"]

    @property
    def delivered(self) -> int:
        return self._counts["delivered"]

    @property
    def failed(self) -> int:
        return self._counts["failed"]

    @property
    def rejected(self) -> int:
        return self._counts["rejected"]

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Start the workers. Idempotent; called on the first enqueue."""
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stopping.clear()
            for n in range(self.workers):
                thread = threading.Thread(
                    target=self._run, name=f"ovms-mail-{n}", daemon=True
                )
                thread.start()
                self._threads.append(thread)
            logger.info("Email queue started with %d worker(s).", self.workers)

    def shutdown(self, drain_timeout: float = 10.0) -> None:
        """Stop accepting, let the workers finish what is already queued."""
        with self._lock:
            if not self._started:
                return
            threads, self._threads = self._threads, []
            self._started = False

        self._stopping.set()
        ready, delayed = self._queue.close()
        if ready or delayed:
            logger.info(
                "Email queue draining: %d message(s) ready, %d awaiting retry.", ready, delayed
            )
        self._queue.wake_all()

        deadline = time.monotonic() + drain_timeout
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

        remaining = self._queue.size()
        if remaining:
            logger.warning(
                "Email queue shut down with %d undelivered message(s); the queue is "
                "in-memory, so they are lost.", remaining
            )

    # -- producer side ----------------------------------------------------

    def enqueue(
        self,
        recipient_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        priority: Priority = Priority.NORMAL,
    ) -> bool:
        """Accept a message for delivery.

        Returns whether it was *accepted*, not whether it was delivered — delivery
        happens later, on a worker. Everything that can be checked synchronously is
        checked here, so a bad address is reported to the caller rather than discovered
        by a worker with nobody left to tell.
        """
        if not all([settings.EMAIL_HOST, settings.EMAIL_SENDER, recipient_email]):
            logger.warning(
                "Email server settings (host, sender) or recipient not configured. "
                "Dropping message '%s'.", str(subject)[:60]
            )
            self._bump("rejected")
            return False

        try:
            recipient_email = validate_email_address(recipient_email)
        except InvalidEmailAddress as e:
            logger.error(f"Refusing to queue email: invalid recipient address ({e}).")
            self._bump("rejected")
            return False

        safe_subject = sanitize_header_value(subject)
        if safe_subject != subject:
            logger.warning("Email subject contained control characters; they were removed.")

        message = QueuedEmail(
            recipient=recipient_email,
            subject=safe_subject,
            body_text=body_text,
            body_html=body_html,
            priority=priority,
        )

        size = self._queue.size()
        if priority > Priority.HIGH and size >= self.normal_priority_limit:
            logger.warning(
                "Email queue is at %d/%d; refusing %s-priority message %s. "
                "Capacity above this mark is reserved for time-critical mail.",
                size, self.maxsize, priority.name, message.describe(),
            )
            self._bump("rejected")
            return False

        self.start()
        if not self._queue.put(message):
            logger.error(
                "Email queue is full (%d) or shutting down; dropped %s",
                self.maxsize, message.describe(),
            )
            self._bump("rejected")
            return False

        self._bump("accepted")
        return True

    def stats(self) -> dict:
        """A snapshot for operators.

        `rejected` is the number that matters and the one nothing else surfaces: a
        message refused at the door because the queue was above its priority mark, or
        the address was unusable. It is counted, logged and otherwise invisible.
        """
        with self._counts_lock:
            counts = dict(self._counts)
        return {
            "queued": self._queue.size(),
            **counts,
            "workers": self.workers,
            "running": self._started,
            "capacity": self.maxsize,
            # Above this, only HIGH priority is accepted.
            "normal_priority_limit": self.normal_priority_limit,
        }

    # -- consumer side ----------------------------------------------------

    def _run(self) -> None:
        session = _SmtpSession()
        consecutive_errors = 0
        try:
            while True:
                # Inside the loop, not around it: a worker that exits is never replaced,
                # so an unexpected error must cost one iteration rather than one of the
                # two workers for the rest of the process's life.
                try:
                    message = self._queue.get(timeout=IDLE_CONNECTION_SECONDS)
                    if message is None:
                        # Idle, or drained during shutdown. Either way the connection has
                        # outlived its usefulness.
                        session.close()
                        if self._stopping.is_set():
                            return
                        continue

                    self._process(session, message)

                    if session.exhausted:
                        logger.debug("Email queue: recycling SMTP connection after %d messages.",
                                     MAX_MESSAGES_PER_CONNECTION)
                        session.close()
                    consecutive_errors = 0
                except Exception:
                    consecutive_errors += 1
                    logger.error(
                        "Email queue worker hit an unexpected error (%d/%d consecutive).",
                        consecutive_errors, MAX_CONSECUTIVE_WORKER_ERRORS, exc_info=True,
                    )
                    session.close()
                    if consecutive_errors >= MAX_CONSECUTIVE_WORKER_ERRORS:
                        logger.critical(
                            "Email queue worker giving up after %d consecutive errors; "
                            "outbound mail capacity is reduced until the next restart.",
                            consecutive_errors,
                        )
                        return
                    # Interruptible pause, so a broken worker does not spin and a
                    # shutdown does not have to wait it out.
                    self._stopping.wait(WORKER_ERROR_PAUSE_SECONDS)
        finally:
            session.close()

    def _process(self, session: _SmtpSession, message: QueuedEmail) -> None:
        message.attempts += 1
        try:
            self._deliver(session, message)
        except Exception as e:
            session.close()
            self._handle_failure(message, e)
            return

        self._bump("delivered")
        logger.info(f"Email delivered: {message.describe()}")

    def _deliver(self, session: _SmtpSession, message: QueuedEmail) -> None:
        """Send one message, reconnecting once if the pooled connection went away."""
        try:
            smtp_channel.deliver(session.server(), message.recipient, message.subject,
                                 message.body_text, message.body_html)
        except smtplib.SMTPServerDisconnected:
            # The common case is a provider closing an idle connection between messages.
            # Reconnecting immediately is cheaper and far less visible than treating it
            # as a failure and waiting out a backoff.
            logger.debug("Email queue: SMTP connection was closed by the server; reconnecting.")
            session.close()
            smtp_channel.deliver(session.server(), message.recipient, message.subject,
                                 message.body_text, message.body_html)
        session.note_sent()

    def _handle_failure(self, message: QueuedEmail, error: Exception) -> None:
        # One classification, shared with the inline retry decorator: `is_transient()`
        # reads the SMTP reply code, so a 5xx rejection is permanent and a 4xx (a
        # greylisting 450, a 421 "try again later") is not. This used to special-case
        # two exception classes here and treat everything else smtplib raised as
        # transient, because SMTPException derives from OSError.
        if not is_transient(error):
            self._bump("failed")
            logger.error(f"Email permanently failed ({error}); dropping {message.describe()}")
            return

        if message.attempts > len(RETRY_DELAYS_SECONDS) or message.attempts >= self.max_attempts:
            self._bump("failed")
            logger.error(
                f"Email gave up after {message.attempts} attempt(s) ({error}); "
                f"dropping {message.describe()}"
            )
            return

        base = RETRY_DELAYS_SECONDS[message.attempts - 1]
        delay = base * (1 + random.random() * 0.25)
        logger.warning(
            f"Email attempt {message.attempts} failed ({error}); retrying "
            f"{message.describe()} in {delay:.0f}s."
        )
        # force=True: this message already holds a slot as far as the caller is
        # concerned, and refusing it here because the queue filled up in the meantime
        # would silently discard something already accepted.
        if not self._queue.put(message, delay=delay, force=True):
            self._bump("failed")
            logger.error(f"Email queue closed before retry; dropping {message.describe()}")


# Named mail_queue, not email_queue: the module is already called email_queue, and a
# singleton sharing its name makes `from app.notifications import email_queue` return
# whichever of the two the importer did not mean.
mail_queue = EmailQueue()


def queue_email_notification(
    recipient_email: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    priority: Priority = Priority.NORMAL,
) -> bool:
    """Hand a message to the queue. True means accepted, not delivered."""
    return mail_queue.enqueue(recipient_email, subject, body_text, body_html, priority)


def shutdown_email_queue(drain_timeout: float = 10.0) -> None:
    mail_queue.shutdown(drain_timeout=drain_timeout)
