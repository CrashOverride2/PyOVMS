"""Per-vehicle notification rate limiting.

"""

import logging
import threading
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Sustained rate: one notification per vehicle per this many seconds.
DEFAULT_INTERVAL_SECONDS = 10.0

# How many notifications may arrive back-to-back before the sustained rate applies.
# Sized for the largest burst a well-behaved module actually produces.
DEFAULT_BURST = 4

# Backstop for the tracking table. The dispatcher checks the limit before it knows
# whether the vehicle exists (deliberately — that check is a database round trip and the
# limiter is what shields it), so the key space is whatever a publisher sends.
MAX_TRACKED_VEHICLES = 10_000


class NotificationRateLimiter:
    """Thread-safe token-bucket limiter keyed on vehicle id.

    `burst=1` degenerates to the old minimum-interval behaviour, which is what the
    tests that pin the interval semantics use.
    """

    def __init__(self, interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
                 max_tracked: int = MAX_TRACKED_VEHICLES,
                 burst: int = DEFAULT_BURST):
        self.interval_seconds = interval_seconds
        self.max_tracked = max_tracked
        self.burst = max(1, burst)
        # vehicle_id -> (tokens available, monotonic time the count refers to)
        self._last_seen: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, vehicle_id: str) -> Optional[float]:
        """Claim a send slot.

        Returns None when the caller may send, or the age in seconds of the previous
        notification when it must be suppressed. None rather than 0.0 so that two calls
        landing in the same clock tick are not read as "allowed".
        """
        now = time.monotonic()

        # An interval of zero means "no limit"; it is also the only value that would
        # make the refill below divide by zero.
        if self.interval_seconds <= 0:
            with self._lock:
                self._last_seen[vehicle_id] = (float(self.burst), now)
                self._evict_locked(now)
            return None

        with self._lock:
            tokens, stamped_at = self._last_seen.get(vehicle_id, (float(self.burst), now))
            # Refill for the time that has passed, capped at the burst size.
            tokens = min(float(self.burst), tokens + (now - stamped_at) / self.interval_seconds)

            if tokens < 1.0:
                # Report the age of the previous notification, which is what the caller
                # logs. With an empty bucket that is the time since it was last stamped.
                return now - stamped_at

            self._last_seen[vehicle_id] = (tokens - 1.0, now)
            self._evict_locked(now)
        return None

    def _evict_locked(self, now: float) -> None:
        # An entry whose bucket has had time to refill completely can no longer suppress
        # anything, so dropping it cannot change a decision. The hard cap is the backstop
        # for a burst of distinct ids inside a single window, where every entry is still
        # live.
        cutoff = now - (self.interval_seconds * (self.burst + 1))
        for key in [k for k, (_tokens, stamped_at) in self._last_seen.items() if stamped_at < cutoff]:
            del self._last_seen[key]
        if len(self._last_seen) > self.max_tracked:
            logger.warning(
                "Notification rate-limit table exceeded %d vehicles; clearing it. "
                "This means an unusual number of distinct vehicle ids are publishing.",
                self.max_tracked,
            )
            self._last_seen.clear()

    def reset(self) -> None:
        with self._lock:
            self._last_seen.clear()


def _configured_limiter() -> NotificationRateLimiter:
    """The process-wide limiter, sized from settings.

    Imported here rather than at module scope so this module stays importable without
    the settings object — it is otherwise a leaf with no dependencies at all.
    """
    from app.config import settings

    return NotificationRateLimiter(
        interval_seconds=settings.NOTIFY_RATE_LIMIT_INTERVAL_SECONDS,
        burst=settings.NOTIFY_RATE_LIMIT_BURST,
    )


rate_limiter = _configured_limiter()
