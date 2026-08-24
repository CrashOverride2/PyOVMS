"""Fixed-size worker pools fed by a *bounded* queue.

`concurrent.futures.ThreadPoolExecutor` is the obvious tool and the wrong one for the
job this module exists for: its work queue is unbounded. A producer that outruns the
workers therefore never finds out. The backlog simply grows — in memory, invisibly —
and every item in it is delivered later than the one before. Nothing fails, nothing is
logged, and the observable symptom is that messages arrive hours after the event that
produced them.

A bounded queue forces the overflow decision to be made explicitly at each call site:

* ``BLOCK``       — back-pressure: the producer waits. Correct when the items are data
                    that must not be lost. For an MQTT callback this also hands the
                    flow control back to the broker, which is where it belongs.
* ``DROP_OLDEST`` — freshness wins. Correct for push notifications: a two-hour-old
                    "charge complete" helps nobody, and if something has to go it
                    should be the stalest item, not the one that just arrived.
* ``DROP_NEWEST`` — refuse admission and keep what is already queued.

Every drop is counted and logged (rate-limited, because the situation that causes one
drop causes thousands), so shedding load is visible instead of silent.
"""

import logging
import threading
import time
from collections import deque
from enum import Enum
from typing import Callable, Deque, Optional, Tuple

logger = logging.getLogger(__name__)

# Gap between two "the queue is full" log records from the same pool. Without it the
# overflow message is emitted once per dropped item, which is precisely when the log is
# least able to absorb it.
_OVERFLOW_LOG_INTERVAL_SECONDS = 30.0


class OverflowPolicy(str, Enum):
    BLOCK = "block"
    DROP_OLDEST = "drop_oldest"
    DROP_NEWEST = "drop_newest"


_Job = Tuple[Callable[..., object], tuple, dict]


class BoundedWorkerPool:
    """A fixed number of daemon threads consuming a bounded FIFO of callables.

    Jobs must not raise: `submit` reports admission, never the outcome. Anything a job
    raises is logged and swallowed, because a worker thread that dies is not replaced
    and would silently reduce the pool to nothing.
    """

    def __init__(
        self,
        name: str,
        workers: int,
        maxsize: int,
        overflow: OverflowPolicy = OverflowPolicy.BLOCK,
        block_timeout: Optional[float] = 30.0,
    ):
        if workers < 1:
            raise ValueError("a worker pool needs at least one worker")
        if maxsize < 1:
            raise ValueError("a bounded queue needs room for at least one job")

        self.name = name
        self.workers = workers
        self.maxsize = maxsize
        self.overflow = overflow
        # Only meaningful for BLOCK. None means "wait indefinitely"; a number bounds how
        # long a producer may be held, so a wedged worker cannot stall an MQTT network
        # thread for the lifetime of the process.
        self.block_timeout = block_timeout

        self._queue: Deque[_Job] = deque()
        self._cv = threading.Condition()
        self._threads: list = []
        self._started = False
        self._closed = False
        self._start_lock = threading.Lock()

        self._counts = {"accepted": 0, "dropped": 0, "completed": 0, "failed": 0, "blocked": 0}
        self._counts_lock = threading.Lock()
        self._last_overflow_log = 0.0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Start the workers. Idempotent; `submit` calls it on first use."""
        with self._start_lock:
            if self._started or self._closed:
                return
            self._started = True
            for n in range(self.workers):
                thread = threading.Thread(target=self._run, name=f"{self.name}-{n}", daemon=True)
                thread.start()
                self._threads.append(thread)
            logger.info(
                "Worker pool '%s' started: %d worker(s), queue limit %d, overflow=%s.",
                self.name, self.workers, self.maxsize, self.overflow.value,
            )

    def shutdown(self, drain_timeout: float = 10.0) -> int:
        """Stop accepting, let the workers finish what is queued, and join them.

        Returns the number of jobs still undone when the timeout expired. Blocking, so
        call it off the event loop.
        """
        with self._start_lock:
            # Marked closed under the same lock `start()` uses, not afterwards: in the
            # gap between the two, a concurrent submit() would see a pool that is neither
            # started nor closed and start a fresh set of worker threads behind us.
            self._closed = True
            if not self._started:
                return 0
            threads, self._threads = self._threads, []
            self._started = False

        with self._cv:
            self._cv.notify_all()

        deadline = time.monotonic() + drain_timeout
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

        with self._cv:
            remaining = len(self._queue)
        if remaining:
            logger.warning(
                "Worker pool '%s' shut down with %d job(s) still queued; they are lost.",
                self.name, remaining,
            )
        return remaining

    # -- producing --------------------------------------------------------

    def submit(self, fn: Callable[..., object], *args, **kwargs) -> bool:
        """Queue a job. The return value is about *this* job and nothing else.

        False means this job was not queued: the pool is closed, DROP_NEWEST refused it,
        or a BLOCK wait timed out. Under DROP_OLDEST the answer is True even though room
        was made by discarding something older — that displaced job is reported by the
        drop counter and the overflow log, not here, because a caller acting on the
        return value is asking about the item it just handed over.
        """
        if self._closed:
            return False
        if not self._started:
            self.start()

        with self._cv:
            if self._closed:
                return False

            if len(self._queue) >= self.maxsize:
                if self.overflow is OverflowPolicy.BLOCK:
                    if not self._wait_for_room_locked():
                        self._bump("dropped")
                        self._log_overflow(
                            "waited %.0fs for room and gave up" % (self.block_timeout or 0.0)
                        )
                        return False
                elif self.overflow is OverflowPolicy.DROP_NEWEST:
                    self._bump("dropped")
                    self._log_overflow("refused the newest job")
                    return False
                else:  # DROP_OLDEST
                    self._queue.popleft()
                    self._bump("dropped")
                    self._log_overflow("discarded the oldest queued job")

            self._queue.append((fn, args, kwargs))
            self._cv.notify()

        self._bump("accepted")
        return True

    def _wait_for_room_locked(self) -> bool:
        """Wait until the queue has room. Caller holds the condition."""
        self._bump("blocked")
        deadline = None if self.block_timeout is None else time.monotonic() + self.block_timeout
        while len(self._queue) >= self.maxsize:
            if self._closed:
                return False
            if deadline is None:
                self._cv.wait(1.0)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._cv.wait(remaining)
        return not self._closed

    # -- consuming --------------------------------------------------------

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._queue:
                    if self._closed:
                        return
                    self._cv.wait(1.0)
                fn, args, kwargs = self._queue.popleft()
                # A producer may be parked in _wait_for_room_locked().
                self._cv.notify_all()

            try:
                fn(*args, **kwargs)
                self._bump("completed")
            except Exception:
                self._bump("failed")
                logger.error(
                    "Worker pool '%s': a job raised and was discarded.", self.name, exc_info=True
                )

    # -- diagnostics ------------------------------------------------------

    def _bump(self, key: str) -> None:
        with self._counts_lock:
            self._counts[key] += 1

    def _log_overflow(self, what: str) -> None:
        """Rate-limited overflow warning. Caller holds the condition."""
        now = time.monotonic()
        if now - self._last_overflow_log < _OVERFLOW_LOG_INTERVAL_SECONDS:
            return
        self._last_overflow_log = now
        logger.warning(
            "Worker pool '%s' is saturated (%d/%d queued, %d worker(s)) and %s. "
            "Total dropped so far: %d.",
            self.name, len(self._queue), self.maxsize, self.workers, what,
            self._counts["dropped"],
        )

    def qsize(self) -> int:
        with self._cv:
            return len(self._queue)

    def stats(self) -> dict:
        with self._counts_lock:
            counts = dict(self._counts)
        counts.update(
            name=self.name,
            workers=self.workers,
            maxsize=self.maxsize,
            overflow=self.overflow.value,
            queued=self.qsize(),
        )
        return counts
