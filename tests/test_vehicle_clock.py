"""
The vehicle's clock is a correction, not a timestamp.

An idle OVMS module wakes every 5-10 minutes and publishes its changed metrics in one
burst. The metrics subscriber used to read the *cached* `m.time.utc` while handling
every message of that burst, which meant two things:

  * a metric that arrived now was stamped with the module's clock reading from its
    previous wake-up -- silently, whenever that reading happened to fall inside the
    300s plausibility window. last_seen_v3, last_message_at and the start/end times of
    a charge session all come from that stamp;
  * and when it fell outside the window, one identical warning was logged per message
    in the burst. A single wake-up of one healthy module produced 21 lines saying its
    clock was 601s from server time. 601s was the publish interval, not a skew.

The offset is now measured once, when `m.time.utc` itself arrives, and applied to
everything else. A module with a correct clock and a 10 minute publish interval is
silent.
"""

import datetime
import logging
import time

import pytest

from app.mqtt_metrics_subscriber import MqttMetricsSubscriber

UTC = datetime.timezone.utc
LOGGER_NAME = "app.mqtt_metrics_subscriber"

# The metrics a module actually pushes when it wakes up, trimmed to a realistic burst.
BURST = [
    "v.b.soc", "v.b.voltage", "v.b.current", "v.b.temp", "v.b.range.est",
    "v.p.latitude", "v.p.longitude", "v.p.altitude", "v.p.direction", "v.p.odometer",
    "v.c.state", "v.c.mode", "v.e.temp", "v.e.parktime", "v.e.awake",
    "m.net.sq", "m.net.provider", "m.freeram", "m.tasks", "m.monotonic",
]


@pytest.fixture
def subscriber():
    return MqttMetricsSubscriber()


def clock_reading(moment: datetime.datetime) -> str:
    """The module's wire format: '2025-10-29 19:35:30 UTC'."""
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# The reported symptom: one wake-up, twenty-one warnings
# ---------------------------------------------------------------------------


def test_idle_burst_from_a_healthy_module_logs_nothing(subscriber, caplog):
    """
    Ten minutes of silence followed by a full burst. The module's clock is correct, so
    there is nothing to warn about -- yet this was the exact shape that produced 21
    warnings, because every message in the burst was compared against the m.time.utc
    of the *previous* burst.
    """
    first_wake = datetime.datetime(2026, 9, 4, 17, 57, 34, tzinfo=UTC)
    second_wake = first_wake + datetime.timedelta(seconds=600)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        subscriber._resolve_timestamp(
            "AL6432", "m.time.utc", clock_reading(first_wake), False, first_wake
        )
        for metric in BURST:
            subscriber._resolve_timestamp("AL6432", metric, "1", False, second_wake)
        subscriber._resolve_timestamp(
            "AL6432", "m.time.utc", clock_reading(second_wake), False, second_wake
        )

    assert caplog.records == [], (
        "a correct clock and a 10 minute publish interval must not be reported as skew"
    )


def test_a_burst_is_stamped_with_arrival_time_not_the_previous_wake_up(subscriber):
    """
    The silent half of the same bug: with a 5 minute interval the stale reading stayed
    inside the plausibility window, so no warning was logged and every metric of the
    burst was back-dated by up to 5 minutes.
    """
    first_wake = datetime.datetime(2026, 9, 4, 18, 2, 32, tzinfo=UTC)
    second_wake = first_wake + datetime.timedelta(seconds=290)

    subscriber._resolve_timestamp(
        "HHXX593E", "m.time.utc", clock_reading(first_wake), False, first_wake
    )

    stamped = subscriber._resolve_timestamp("HHXX593E", "v.b.soc", "64", False, second_wake)

    assert abs((stamped - second_wake).total_seconds()) < 1, (
        f"metric stamped {(second_wake - stamped).total_seconds():.0f}s in the past"
    )


# ---------------------------------------------------------------------------
# What the vehicle clock is still allowed to do
# ---------------------------------------------------------------------------


def test_a_plausible_offset_is_measured_and_applied(subscriber):
    """A module running 8s fast keeps running 8s fast between wake-ups."""
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)
    ahead = now + datetime.timedelta(seconds=8)

    on_time_metric = subscriber._resolve_timestamp(
        "LASSE", "m.time.utc", clock_reading(ahead), False, now
    )
    assert on_time_metric == ahead

    later = now + datetime.timedelta(seconds=42)
    stamped = subscriber._resolve_timestamp("LASSE", "v.b.soc", "80", False, later)

    assert abs((stamped - later).total_seconds() - 8) < 1


def test_a_stale_offset_is_dropped_rather_than_carried_forever(subscriber):
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)
    expired = time.monotonic() - subscriber.CLOCK_OFFSET_TTL_SECONDS - 1
    subscriber._clock_offsets["BLUESKYX"] = (250.0, expired)

    stamped = subscriber._resolve_timestamp("BLUESKYX", "v.b.soc", "51", False, now)

    assert stamped == now
    assert "BLUESKYX" not in subscriber._clock_offsets


def test_a_module_that_never_publishes_its_clock_uses_server_time(subscriber):
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)

    assert subscriber._resolve_timestamp("QUIET", "v.b.soc", "51", False, now) == now


@pytest.mark.parametrize("payload", ["", None, "not a date", "2026-13-45 99:99:99 UTC"])
def test_an_unparseable_clock_reading_falls_back_to_server_time(subscriber, payload):
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)

    assert subscriber._resolve_timestamp("TESTCAR", "m.time.utc", payload, False, now) == now
    assert "TESTCAR" not in subscriber._clock_offsets


# ---------------------------------------------------------------------------
# M-8 still holds: a broken clock is ignored, and said once
# ---------------------------------------------------------------------------


def test_a_far_future_clock_is_ignored_and_forgets_any_earlier_offset(subscriber, caplog):
    """
    `m.time.utc = 9999-01-01` pinned the car "online" forever. It must not be believed,
    and it must not leave a usable offset behind for the rest of the burst either.
    """
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)
    subscriber._clock_offsets["BROKEN"] = (3.0, time.monotonic())

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        stamped = subscriber._resolve_timestamp(
            "BROKEN", "m.time.utc", "9999-01-01 00:00:00 UTC", False, now
        )

    assert stamped == now
    assert "BROKEN" not in subscriber._clock_offsets
    assert len(caplog.records) == 1
    assert "implausible" in caplog.records[0].message

    later = now + datetime.timedelta(seconds=5)
    assert subscriber._resolve_timestamp("BROKEN", "v.b.soc", "51", False, later) == later


def test_a_permanently_broken_clock_is_reported_once_per_interval(subscriber, caplog):
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        for wake in range(6):
            subscriber._resolve_timestamp(
                "BROKEN", "m.time.utc", "9999-01-01 00:00:00 UTC",
                False, now + datetime.timedelta(seconds=600 * wake),
            )

        assert len(caplog.records) == 1, "one line per wake-up is still six lines an hour"

        # ...but the vehicle is not muted forever.
        subscriber._clock_warned_at["BROKEN"] = (
            time.monotonic() - subscriber.CLOCK_WARNING_INTERVAL_SECONDS - 1
        )
        subscriber._resolve_timestamp(
            "BROKEN", "m.time.utc", "9999-01-01 00:00:00 UTC", False, now
        )

    assert len(caplog.records) == 2


def test_a_retained_clock_reading_neither_measures_nor_warns(subscriber, caplog):
    """
    On subscriber reconnect the broker replays retained metrics. A retained
    `m.time.utc` is old by an unknowable amount: it is not evidence of a broken clock,
    and it cannot measure an offset.
    """
    now = datetime.datetime(2026, 9, 4, 18, 7, 34, tzinfo=UTC)
    long_ago = now - datetime.timedelta(hours=6)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        stamped = subscriber._resolve_timestamp(
            "PARKED", "m.time.utc", clock_reading(long_ago), True, now
        )

    assert stamped == now
    assert caplog.records == []
    assert "PARKED" not in subscriber._clock_offsets


def test_the_skew_limit_is_still_tight():
    assert 0 < MqttMetricsSubscriber.MAX_VEHICLE_CLOCK_SKEW_SECONDS <= 3600
