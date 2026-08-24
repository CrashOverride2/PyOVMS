"""Deferred re-execution, so that waiting costs nothing.

The push channels used to retry inline: a transient failure slept 5 s, then 10 s, on
the worker thread that was doing the send. That thread came from a small, *shared*
pool, so the arithmetic was unforgiving — with eight fan-out workers and a push host
that had gone quiet, the whole subsystem's throughput fell to eight messages per
fifteen seconds, and everything behind them queued. Notifications for vehicles with
perfectly healthy recipients were delayed by the retry budget of the unhealthy ones.

Nothing about waiting requires a thread. This module keeps the due times on a heap and
one timer thread watching the earliest of them; when an item comes due it is handed
back to the pool that runs sends. Between attempts the retry occupies a heap entry and
nothing else.

The mail queue solved the same problem the same way (`_PriorityDelayQueue`), for the
same reason. This is the push-side counterpart — smaller, because push retries have no
priorities and no connection to reuse.
"""

import heapq
import itertools
import logging
import threading
import time
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DelayedRetryScheduler:
    """Run callables after a delay, without holding a worker while waiting.

    `runner` is how a due item gets executed — normally "submit to the fan-out pool".
    It must not block: the timer thread calls it, and a runner that blocks delays every
    other scheduled retry.
    """

    def __init__(
        self,
        name: str,
        runner: Callable[[Callable[[], None]], None],
        max_pending: int = 5_000,
    ):
        self.name = name
        self._runner = runner
        self.max_pending = max_pending

        self._heap: List[Tuple[float, int, Callable[[], None]]] = []
        self._seq = itertools.count()
        self._cv = threading.Condition()
        self._thread: Optional[threading.Thread] = None
        self._closed = False
        self._dropped = 0

    def schedule(self, delay: float, fn: Callable[[], None]) -> bool:
        """Run `fn` in `delay` seconds. False when the scheduler is closed or full."""
        with self._cv:
            if self._closed:
                return False
            if len(self._heap) >= self.max_pending:
                self._dropped += 1
                logger.warning(
                    "Retry scheduler '%s' is full (%d pending); dropping a retry. "
                    "Total dropped: %d.",
                    self.name, self.max_pending, self._dropped,
                )
                return False
            heapq.heappush(self._heap, (time.monotonic() + delay, next(self._seq), fn))
            self._cv.notify()
        self._ensure_thread()
        return True

    def _ensure_thread(self) -> None:
        with self._cv:
            if self._closed or (self._thread is not None and self._thread.is_alive()):
                return
            self._thread = threading.Thread(
                target=self._run, name=f"{self.name}-timer", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            with self._cv:
                while True:
                    if self._closed:
                        return
                    if not self._heap:
                        # Nothing pending: park. A fresh schedule() notifies us.
                        self._cv.wait(5.0)
                        if self._closed:
                            return
                        continue
                    wait = self._heap[0][0] - time.monotonic()
                    if wait <= 0:
                        break
                    self._cv.wait(wait)
                _due, _seq, fn = heapq.heappop(self._heap)

            try:
                self._runner(fn)
            except Exception:
                logger.error(
                    "Retry scheduler '%s' could not hand a due retry to its runner.",
                    self.name, exc_info=True,
                )

    def pending(self) -> int:
        with self._cv:
            return len(self._heap)

    def stats(self) -> dict:
        with self._cv:
            return {"name": self.name, "pending": len(self._heap), "dropped": self._dropped}

    def shutdown(self, wait_timeout: float = 5.0) -> int:
        """Stop the timer thread. Returns how many retries were still pending.

        Deliberately does not run them: they are, by definition, sends that already
        failed once and are waiting on a timer. Holding shutdown open for the full
        backoff of a host that is not answering is the worse trade.
        """
        with self._cv:
            if self._closed:
                return 0
            self._closed = True
            pending = len(self._heap)
            self._heap.clear()
            thread = self._thread
            self._thread = None
            self._cv.notify_all()

        if thread is not None:
            thread.join(timeout=wait_timeout)
        if pending:
            logger.info(
                "Retry scheduler '%s' shut down with %d pending retry/retries, dropped.",
                self.name, pending,
            )
        return pending
