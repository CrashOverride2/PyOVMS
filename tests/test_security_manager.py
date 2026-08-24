"""
Regression tests for the rate limiter and IP blocking.

Covers three defects that reinforced each other:
  H-2  automated blocks lasted ten years, which is a denial-of-service primitive once
       an IP is shared (CGNAT, corporate NAT).
  M-7  the in-memory failure counter was never trimmed to the sliding window, so an IP
       with four failures spread over weeks was blocked on the fifth.
  M-2  BlockedIP.unblock_at comes back naive from SQLite; calling .timestamp() on it
       treats UTC as local time, so east of UTC a restored block was already expired.
"""

import datetime
import time

from app.security_manager import SecurityManager, _as_utc_timestamp


# --- M-2: timezone handling of persisted blocks ---------------------------------

def test_naive_datetime_is_read_as_utc_not_local():
    aware = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    naive = aware.replace(tzinfo=None)  # what SQLite hands back
    assert _as_utc_timestamp(naive) == aware.timestamp()


def test_aware_datetime_is_left_alone():
    aware = datetime.datetime.now(datetime.timezone.utc)
    assert _as_utc_timestamp(aware) == aware.timestamp()


def test_restored_one_hour_block_is_still_in_the_future():
    """The concrete failure: a 60-minute block must survive a restart in any timezone."""
    unblock_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)
    assert _as_utc_timestamp(unblock_at.replace(tzinfo=None)) > time.time()


# --- H-2: automated blocks must stay bounded ------------------------------------

def test_no_automated_block_lasts_longer_than_a_day():
    manager = SecurityManager()
    assert manager.extended_block_duration_minutes <= 24 * 60
    assert not hasattr(manager, "permanent_lockout_threshold"), (
        "permanent automated lockouts are a DoS primitive on shared/NAT addresses"
    )


def test_block_duration_is_positive_and_finite():
    manager = SecurityManager()
    assert 0 < manager.block_duration_minutes <= manager.extended_block_duration_minutes


# --- M-7: the in-memory counter must respect the sliding window ------------------

def test_failures_outside_the_window_are_discarded():
    manager = SecurityManager()
    ip = "203.0.113.9"
    window = manager.time_windows["login"]

    # Four failures, all older than the window.
    stale = time.time() - (window + 60)
    manager.failed_attempts[ip]["login"] = [stale] * 4

    manager.sweep_stale_username_entries()
    assert ip not in manager.failed_attempts, "stale per-IP entries must be swept"


def test_sweep_keeps_failures_inside_the_window():
    manager = SecurityManager()
    ip = "203.0.113.10"
    manager.failed_attempts[ip]["login"] = [time.time()]
    manager.sweep_stale_username_entries()
    assert manager.failed_attempts[ip]["login"], "recent failures must not be swept"


def test_sweep_bounds_memory_growth_across_many_ips():
    """An attacker spraying from many addresses must not grow the dict forever."""
    manager = SecurityManager()
    stale = time.time() - 10_000
    for i in range(500):
        manager.failed_attempts[f"198.51.100.{i % 256}-{i}"]["login"] = [stale]
    manager.sweep_stale_username_entries()
    assert len(manager.failed_attempts) == 0
