"""
The queues between an MQTT message and a delivered notification.

This suite exists because of a production symptom rather than a code smell: on a server
with a fleet on it, module notifications were arriving up to two hours after the event.
Nothing failed, nothing was logged. Three separate unbounded waits added up to it:

  * history records were stored inline on paho's single network thread, so every push
    notification queued behind the database work of every record before it;
  * the pool that ran the dispatches had an unbounded queue, so once the workers fell
    behind, the backlog grew instead of being reported;
  * a failing send slept through its own retry on a worker from a small shared pool,
    so one unreachable push host removed capacity from every other vehicle.

What is asserted here is that each of those is now bounded, visible, or deferred.
"""

import threading
import time

import pytest

from app.notifications.scheduler import DelayedRetryScheduler
from app.utils.bounded_worker import BoundedWorkerPool, OverflowPolicy


# ---------------------------------------------------------------------------
# the queue is bounded, and says so
# ---------------------------------------------------------------------------

def test_drop_oldest_keeps_the_newest_work():
    """Freshness wins for notifications: an hour-old alert helps nobody."""
    done = []

    pool = BoundedWorkerPool(
        "test-drop-oldest", workers=1, maxsize=2, overflow=OverflowPolicy.DROP_OLDEST
    )
    release = _occupy(pool)
    try:
        for n in range(6):
            assert pool.submit(done.append, n) is True

        release.set()
        _drain(pool, expected_finished=3)
    finally:
        release.set()
        pool.shutdown(drain_timeout=5.0)

    assert done == [4, 5], "the queue kept the stalest jobs instead of the freshest"
    assert pool.stats()["dropped"] == 4


def test_drop_newest_refuses_admission():
    pool = BoundedWorkerPool(
        "test-drop-newest", workers=1, maxsize=1, overflow=OverflowPolicy.DROP_NEWEST
    )
    release = _occupy(pool)
    try:
        assert pool.submit(lambda: None) is True    # fills the queue
        assert pool.submit(lambda: None) is False   # refused
    finally:
        release.set()
        pool.shutdown(drain_timeout=5.0)


def test_blocking_pool_applies_back_pressure_instead_of_dropping():
    """
    The history-record path must not drop: a lost record is a permanent hole in a
    vehicle's history, where a lost notification is one missed alert. The producer waits.
    """
    seen = []
    pool = BoundedWorkerPool(
        "test-block", workers=1, maxsize=1, overflow=OverflowPolicy.BLOCK, block_timeout=5.0
    )
    release = _occupy(pool)
    try:
        pool.submit(seen.append, "queued")

        producer_returned = threading.Event()

        def producer():
            pool.submit(seen.append, "blocked")
            producer_returned.set()

        thread = threading.Thread(target=producer, daemon=True)
        thread.start()

        assert not producer_returned.wait(0.3), "the producer was not held back"
        release.set()
        assert producer_returned.wait(5.0), "the producer was never released"
        thread.join(timeout=5.0)
        _drain(pool, expected_finished=3)
    finally:
        release.set()
        pool.shutdown(drain_timeout=5.0)

    assert seen == ["queued", "blocked"]
    assert pool.stats()["dropped"] == 0


def test_a_blocked_producer_is_released_by_shutdown():
    """Otherwise a wedged worker holds the MQTT network thread until the process dies."""
    pool = BoundedWorkerPool(
        "test-block-shutdown", workers=1, maxsize=1, overflow=OverflowPolicy.BLOCK,
        block_timeout=None,
    )
    release = _occupy(pool)
    pool.submit(lambda: None)

    returned = threading.Event()
    threading.Thread(
        target=lambda: (pool.submit(lambda: None), returned.set()), daemon=True
    ).start()

    assert not returned.wait(0.3)
    pool.shutdown(drain_timeout=0.5)
    release.set()
    assert returned.wait(5.0), "shutdown left a producer parked forever"


def test_a_job_that_raises_does_not_kill_its_worker():
    """Nothing replaces a dead worker, so one bad job would shrink the pool for good."""
    done = []
    pool = BoundedWorkerPool("test-raises", workers=1, maxsize=10)
    try:
        pool.submit(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        pool.submit(done.append, "after")
        _drain(pool, expected_finished=2)
    finally:
        pool.shutdown(drain_timeout=5.0)

    assert done == ["after"]
    assert pool.stats()["failed"] == 1


def test_submitting_after_shutdown_is_refused():
    pool = BoundedWorkerPool("test-closed", workers=1, maxsize=10)
    pool.submit(lambda: None)
    pool.shutdown(drain_timeout=5.0)

    assert pool.submit(lambda: None) is False
    assert not [t for t in threading.enumerate() if t.name.startswith("test-closed")]


@pytest.mark.parametrize("workers,maxsize", [(0, 10), (1, 0)])
def test_a_pool_without_capacity_is_a_configuration_error(workers, maxsize):
    with pytest.raises(ValueError):
        BoundedWorkerPool("test-invalid", workers=workers, maxsize=maxsize)


# ---------------------------------------------------------------------------
# waiting for a retry costs a heap entry, not a thread
# ---------------------------------------------------------------------------

def test_a_scheduled_retry_runs_without_occupying_a_thread_meanwhile():
    ran = threading.Event()
    scheduler = DelayedRetryScheduler("test-retry", runner=lambda fn: fn())
    try:
        assert scheduler.schedule(0.05, ran.set) is True
        assert scheduler.pending() == 1
        assert ran.wait(5.0), "the scheduled retry never ran"
        assert scheduler.pending() == 0
    finally:
        scheduler.shutdown()


def test_retries_run_in_due_order_not_submission_order():
    order = []
    scheduler = DelayedRetryScheduler("test-order", runner=lambda fn: fn())
    finished = threading.Event()
    try:
        scheduler.schedule(0.30, lambda: (order.append("late"), finished.set()))
        scheduler.schedule(0.05, lambda: order.append("early"))
        assert finished.wait(5.0)
    finally:
        scheduler.shutdown()

    assert order == ["early", "late"]


def test_the_scheduler_is_bounded():
    """A push host that is down produces one pending retry per target per notification."""
    scheduler = DelayedRetryScheduler("test-bounded", runner=lambda fn: fn(), max_pending=3)
    try:
        accepted = [scheduler.schedule(60.0, lambda: None) for _ in range(6)]
        assert accepted == [True, True, True, False, False, False]
        assert scheduler.stats()["dropped"] == 3
    finally:
        scheduler.shutdown()


def test_shutdown_drops_pending_retries_rather_than_waiting_out_a_dead_host():
    scheduler = DelayedRetryScheduler("test-shutdown", runner=lambda fn: fn())
    scheduler.schedule(3600.0, lambda: None)

    started = time.monotonic()
    assert scheduler.shutdown() == 1
    assert time.monotonic() - started < 5.0
    assert scheduler.schedule(0.01, lambda: None) is False


def test_a_runner_that_raises_does_not_kill_the_timer_thread():
    ran = threading.Event()

    def flaky_runner(fn):
        if not ran.is_set():
            ran.set()
            raise RuntimeError("pool refused it")
        fn()

    second = threading.Event()
    scheduler = DelayedRetryScheduler("test-runner-raises", runner=flaky_runner)
    try:
        scheduler.schedule(0.05, lambda: None)
        assert ran.wait(5.0)
        scheduler.schedule(0.05, second.set)
        assert second.wait(5.0), "the timer thread died on the first failure"
    finally:
        scheduler.shutdown()


def _occupy(pool: BoundedWorkerPool, timeout: float = 5.0) -> threading.Event:
    """Pin the pool's single worker inside a job, and return the event that frees it.

    Submitting a blocker and carrying on is not enough: the worker picks it up
    asynchronously, so the queue depth the next submit sees is a race. Waiting until the
    blocker is *running* leaves the queue empty and the worker busy, which is the state
    every overflow assertion below depends on.
    """
    running = threading.Event()
    release = threading.Event()

    def blocker():
        running.set()
        release.wait(10.0)

    assert pool.submit(blocker) is True
    assert running.wait(timeout), "the pool never started its worker"
    return release


def _drain(pool: BoundedWorkerPool, expected_finished: int, timeout: float = 5.0) -> None:
    """Wait until `expected_finished` jobs have run.

    Counted rather than inferred from the queue depth: `accepted` includes jobs a
    DROP_OLDEST pool later displaced, so "accepted == completed + failed" is not an
    identity that holds, and an empty queue says nothing about the job still in a
    worker's hands.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stats = pool.stats()
        if stats["completed"] + stats["failed"] >= expected_finished:
            return
        time.sleep(0.01)
    raise AssertionError(f"pool did not drain: {pool.stats()}")
