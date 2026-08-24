"""
VehicleMetricsManager holds every V3 metric of every connected vehicle in process memory,
fed straight from MQTT. Nothing between the broker and this dictionary is under the
server's control, so its three limits — name length, metrics per vehicle, and the TTL
sweep — are the only thing between a misbehaving or hostile publisher and the process
running out of memory.

Those limits had no test. This covers the boundaries rather than the happy path: the
happy path is exercised by every V3 vehicle in production, the caps are exercised by
nobody until they matter.
"""

import pytest

from app.metrics_manager import (
    _MAX_METRIC_NAME_LENGTH,
    _MAX_METRICS_PER_VEHICLE,
    _METRIC_TTL_SECONDS,
    VehicleMetricsManager,
)


@pytest.fixture
def manager():
    """A fresh instance, not the module singleton — tests must not leak into each other or
    into anything else that imports metrics_manager."""
    return VehicleMetricsManager()


class TestChangeDetection:
    """update_metric() returns whether the value changed. Callers use that to decide
    whether to broadcast over WebSocket, so a wrong answer is either a missed dashboard
    update or a broadcast storm."""

    def test_first_write_counts_as_a_change(self, manager):
        assert manager.update_metric("CAR1", "v.b.soc", 80) is True

    def test_identical_rewrite_is_not_a_change(self, manager):
        manager.update_metric("CAR1", "v.b.soc", 80)
        assert manager.update_metric("CAR1", "v.b.soc", 80) is False

    def test_different_value_is_a_change(self, manager):
        manager.update_metric("CAR1", "v.b.soc", 80)
        assert manager.update_metric("CAR1", "v.b.soc", 81) is True

    def test_falsy_values_are_stored_not_skipped(self, manager):
        """0 and "" are legitimate metric values. A truthiness check instead of a
        None check would silently drop 'speed is 0' and 'charge state is empty'."""
        assert manager.update_metric("CAR1", "v.p.speed", 0) is True
        assert manager.get_metric_value("CAR1", "v.p.speed") == 0
        assert manager.update_metric("CAR1", "v.c.state", "") is True
        assert manager.get_metric_value("CAR1", "v.c.state") == ""


class TestMemoryLimits:
    def test_oversized_metric_name_is_rejected(self, manager):
        name = "x" * (_MAX_METRIC_NAME_LENGTH + 1)
        assert manager.update_metric("CAR1", name, 1) is False
        assert manager.get_metrics_for_vehicle("CAR1") in (None, {})

    def test_name_at_exactly_the_limit_is_accepted(self, manager):
        """Off-by-one in the other direction: the cap must not reject a legal name."""
        name = "x" * _MAX_METRIC_NAME_LENGTH
        assert manager.update_metric("CAR1", name, 1) is True

    def test_per_vehicle_cap_stops_new_metrics(self, manager):
        for i in range(_MAX_METRICS_PER_VEHICLE):
            assert manager.update_metric("CAR1", f"m.{i}", i) is True

        assert manager.update_metric("CAR1", "one.too.many", 1) is False
        assert len(manager.get_metrics_for_vehicle("CAR1")) == _MAX_METRICS_PER_VEHICLE

    def test_cap_still_allows_updating_existing_metrics(self, manager):
        """The important half. A cap that also froze known metrics would turn a vehicle
        publishing many metric names into a vehicle whose SOC stops updating — the data
        goes stale rather than the excess being dropped."""
        for i in range(_MAX_METRICS_PER_VEHICLE):
            manager.update_metric("CAR1", f"m.{i}", i)

        assert manager.update_metric("CAR1", "m.0", "new value") is True
        assert manager.get_metric_value("CAR1", "m.0") == "new value"

    def test_cap_is_per_vehicle_not_global(self, manager):
        for i in range(_MAX_METRICS_PER_VEHICLE):
            manager.update_metric("CAR1", f"m.{i}", i)

        assert manager.update_metric("CAR2", "v.b.soc", 50) is True


class TestStaleEviction:
    """evict_stale_metrics() runs hourly from periodic_housekeeping(). Without it the
    memory of every vehicle that ever connected is held until restart."""

    def _age_all_metrics(self, manager, seconds):
        """Backdate the recorded timestamps. The manager uses time.monotonic(), which
        cannot be patched by moving the clock, so the stored values are shifted instead —
        this is what the passage of time looks like from the manager's point of view."""
        for ts_map in manager._metric_timestamps.values():
            for key in ts_map:
                ts_map[key] -= seconds

    def test_fresh_metrics_survive(self, manager):
        manager.update_metric("CAR1", "v.b.soc", 80)
        manager.evict_stale_metrics()
        assert manager.get_metric_value("CAR1", "v.b.soc") == 80

    def test_metrics_past_the_ttl_are_dropped(self, manager):
        manager.update_metric("CAR1", "v.b.soc", 80)
        self._age_all_metrics(manager, _METRIC_TTL_SECONDS + 60)

        manager.evict_stale_metrics()

        assert manager.get_metric_value("CAR1", "v.b.soc") is None

    def test_a_fully_stale_vehicle_is_removed_entirely(self, manager):
        """Not just its metrics. Leaving the empty dictionaries behind is the leak this
        function exists to prevent — one entry per vehicle id ever seen, forever."""
        manager.update_metric("CAR1", "v.b.soc", 80)
        self._age_all_metrics(manager, _METRIC_TTL_SECONDS + 60)

        manager.evict_stale_metrics()

        assert "CAR1" not in manager.vehicle_metrics
        assert "CAR1" not in manager._metric_timestamps

    def test_eviction_is_per_metric_not_per_vehicle(self, manager):
        """A vehicle that still reports SOC but stopped reporting tyre pressure keeps the
        SOC. Dropping the whole vehicle because one metric went quiet would blank a live
        dashboard."""
        manager.update_metric("CAR1", "v.tp.fl.p", 2.4)
        self._age_all_metrics(manager, _METRIC_TTL_SECONDS + 60)
        manager.update_metric("CAR1", "v.b.soc", 80)

        manager.evict_stale_metrics()

        assert manager.get_metric_value("CAR1", "v.b.soc") == 80
        assert manager.get_metric_value("CAR1", "v.tp.fl.p") is None

    def test_eviction_of_an_empty_manager_is_harmless(self, manager):
        manager.evict_stale_metrics()


class TestLookups:
    def test_unknown_vehicle_returns_none(self, manager):
        assert manager.get_metrics_for_vehicle("NOPE") is None
        assert manager.get_metric_value("NOPE", "v.b.soc") is None

    def test_unknown_metric_on_known_vehicle_returns_none(self, manager):
        manager.update_metric("CAR1", "v.b.soc", 80)
        assert manager.get_metric_value("CAR1", "v.p.speed") is None

    def test_lookup_does_not_create_an_entry(self, manager):
        """vehicle_metrics is a defaultdict. Reading through it with [] instead of .get()
        would make every query for an unknown vehicle allocate — including queries driven
        by a request parameter."""
        manager.get_metrics_for_vehicle("GHOST")
        manager.get_metric_value("GHOST", "v.b.soc")
        assert "GHOST" not in manager.vehicle_metrics
