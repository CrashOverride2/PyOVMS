import logging
import time
from typing import Dict, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# Hard limits to prevent unbounded memory growth (Finding #5)
_MAX_METRICS_PER_VEHICLE = 500
_MAX_METRIC_NAME_LENGTH = 128
_METRIC_TTL_SECONDS = 3 * 3600  # evict metrics not updated for 3 hours

class VehicleMetricsManager:
    """
    A singleton class to store the latest vehicle metrics received via MQTT in memory.
    """
    def __init__(self):
        self.vehicle_metrics: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._metric_timestamps: Dict[str, Dict[str, float]] = defaultdict(dict)
        logger.info("VehicleMetricsManager initialized.")

    def update_metric(self, vehicle_id: str, metric_name: str, value: Any) -> bool:
        """Updates a single metric for a vehicle and returns True if the value changed."""
        if len(metric_name) > _MAX_METRIC_NAME_LENGTH:
            logger.warning(f"MetricsManager: Dropping oversized metric name ({len(metric_name)} chars) for {vehicle_id}")
            return False

        vehicle_data = self.vehicle_metrics[vehicle_id]
        if metric_name not in vehicle_data and len(vehicle_data) >= _MAX_METRICS_PER_VEHICLE:
            logger.warning(
                f"MetricsManager: Per-vehicle metric cap ({_MAX_METRICS_PER_VEHICLE}) reached for {vehicle_id}. "
                f"Dropping new metric '{metric_name}'."
            )
            return False

        previous_value = vehicle_data.get(metric_name)
        changed = previous_value != value
        vehicle_data[metric_name] = value
        self._metric_timestamps[vehicle_id][metric_name] = time.monotonic()

        if changed:
            logger.debug(f"MetricsManager: Updated {vehicle_id} -> {metric_name} = {value}")

        return changed

    def evict_stale_metrics(self) -> None:
        """Remove metrics not updated within TTL. Called by periodic housekeeping."""
        cutoff = time.monotonic() - _METRIC_TTL_SECONDS
        evicted_vehicles = []
        for vehicle_id, ts_map in list(self._metric_timestamps.items()):
            stale_keys = [k for k, ts in ts_map.items() if ts < cutoff]
            for key in stale_keys:
                ts_map.pop(key, None)
                self.vehicle_metrics[vehicle_id].pop(key, None)
            if not ts_map:
                evicted_vehicles.append(vehicle_id)
        for vehicle_id in evicted_vehicles:
            self._metric_timestamps.pop(vehicle_id, None)
            self.vehicle_metrics.pop(vehicle_id, None)
        if evicted_vehicles:
            logger.info(f"MetricsManager: Evicted stale metrics for {len(evicted_vehicles)} vehicle(s).")

    def get_metrics_for_vehicle(self, vehicle_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves all latest metrics for a specific vehicle."""
        return self.vehicle_metrics.get(vehicle_id)

    def get_metric_value(self, vehicle_id: str, metric_name: str) -> Any:
        """Retrieves a specific metric value for a vehicle."""
        vehicle_metrics = self.vehicle_metrics.get(vehicle_id)
        if vehicle_metrics:
            return vehicle_metrics.get(metric_name)
        return None

    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Retrieves all metrics for all vehicles."""
        return self.vehicle_metrics

metrics_manager = VehicleMetricsManager()
