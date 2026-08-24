import paho.mqtt.client as mqtt
import logging
import datetime
import time
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app import crud
from app.database import engine
from app.metrics_manager import metrics_manager
from app.utils import mqtt_topic_auth
from app.services.charge_logger.charge_manager import charge_manager
logger = logging.getLogger(__name__)

class MqttMetricsSubscriber:
    """Listens to the MQTT broker for vehicle metrics and updates the DB."""

    LAST_SEEN_WRITE_INTERVAL_SECONDS = 30

    # How far the vehicle's own clock may differ from ours before we stop believing
    # it. Real modules drift by seconds; anything past this is a broken clock or a
    # forged value, and both are better served by server time.
    MAX_VEHICLE_CLOCK_SKEW_SECONDS = 300

    def __init__(self):
        self._client: mqtt.Client = None
        self._SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        # Vehicle/owner resolution is memoised in app.utils.mqtt_topic_auth so both
        # subscribers share one cache and one authorization rule.
        # Monotonic seconds, not wall clock: the throttle must not be steerable by a
        # payload-derived timestamp, and it must survive a system clock adjustment.
        self._last_seen_write_at: dict[str, float] = {}

    def connect(self, username: str, password: str):
        if not settings.MQTT_BROKER_HOST:
            logger.warning("MQTT Metrics Subscriber disabled: Broker host not configured.")
            return

        self._client = mqtt.Client(client_id="pyovms_metrics_subscriber")
        self._client.username_pw_set(username, password)

        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

        try:
            self._client.connect(settings.MQTT_BROKER_HOST, settings.MQTT_BROKER_PORT, 60)
            self._client.loop_start()
        except Exception as e:
            logger.error(f"MQTT Metrics Subscriber failed to connect: {e}", exc_info=True)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("MQTT Metrics Subscriber connected to broker.")
            topic = "ovms/+/+/metric/#"
            client.subscribe(topic)
            logger.info(f"Subscribed to MQTT topic: {topic}")
        else:
            logger.error(f"MQTT Metrics Subscriber connection failed with code {rc}")

    def _on_disconnect(self, client, userdata, rc):
        if rc == 0:
            logger.info("MQTT Metrics Subscriber disconnected cleanly.")
        else:
            logger.warning(f"MQTT Metrics Subscriber disconnected unexpectedly with code {rc}.")

    def _on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) < 5 or parts[3] != 'metric':
                return

            topic_username = parts[1]
            vehicle_id = parts[2].upper()

            # The broker only restricts the topic *prefix* an account may publish under,
            # so the owner segment must be checked against the DB here — otherwise any
            # user with an API key can write metrics into someone else's vehicle.
            if not mqtt_topic_auth.topic_owner_matches(self._SessionLocal, topic_username, vehicle_id):
                return

            metric_name = ".".join(parts[4:])
            if not metric_name or len(parts) > 12:
                logger.debug(f"Dropping metric with excessive topic depth or empty name on {msg.topic}")
                return
            try:
                metric_value = msg.payload.decode('utf-8').strip()
            except UnicodeDecodeError:
                logger.debug(f"Skipping non-UTF-8 payload on topic {msg.topic}")
                return

            # Normalize empty strings to None for consistent handling
            # Empty strings can't be converted to float and cause crashes
            if metric_value == '':
                metric_value = None

            metric_changed = metrics_manager.update_metric(vehicle_id, metric_name, metric_value)

            # Try to get vehicle's actual timestamp from m.time.utc metric
            # Fall back to server time if not available
            vehicle_timestamp = None
            try:
                time_utc_value = metrics_manager.get_metric_value(vehicle_id, "m.time.utc")
                if time_utc_value:
                    # Parse datetime string format: '2025-10-29 19:35:30 UTC'
                    time_str = time_utc_value.strip()
                    if time_str.endswith(' UTC'):
                        time_str = time_str[:-4].strip()
                    vehicle_timestamp = datetime.datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse m.time.utc for vehicle {vehicle_id}: {e}")

            # Use the vehicle's own clock only when it is plausible.
            #
            # This timestamp drives last_seen_v3 (the online indicator), last_message_at
            # and the start/end times of charge sessions — and it arrives as a metric the
            # vehicle publishes. Unchecked, `m.time.utc = 9999-01-01` pinned the car
            # "online" forever, so connection-loss alerts never fired, and the write
            # throttle below (which compared against the same value) suppressed every
            # later update. A clock that far out is wrong whatever the cause, so fall
            # back to server time instead of trusting it.
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            timestamp = now_utc
            if vehicle_timestamp is not None:
                skew = abs((vehicle_timestamp - now_utc).total_seconds())
                if skew <= self.MAX_VEHICLE_CLOCK_SKEW_SECONDS:
                    timestamp = vehicle_timestamp
                else:
                    logger.warning(
                        f"Ignoring implausible m.time.utc for vehicle '{vehicle_id}': "
                        f"{vehicle_timestamp.isoformat()} is {skew:.0f}s from server time; "
                        f"using server time instead."
                    )

            if metric_changed or not msg.retain:
                charge_manager.process_metric(vehicle_id, metric_name, metric_value, timestamp)

            if msg.retain:
                if metric_changed:
                    logger.debug(f"Ignoring last_seen_v3 update for retained message on topic {msg.topic}")
                return

            # Throttle on the server clock, never on the payload-derived timestamp: the
            # latter is partly vehicle-controlled, and a future value would hold the
            # throttle open indefinitely.
            last_write_at = self._last_seen_write_at.get(vehicle_id)
            if last_write_at is not None and (time.monotonic() - last_write_at) < self.LAST_SEEN_WRITE_INTERVAL_SECONDS:
                return

            db = self._SessionLocal()
            try:
                vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
                if not vehicle_db:
                    mqtt_topic_auth.clear_cache()
                    return

                vehicle_db.last_seen_v3 = timestamp
                vehicle_db.last_message_at = timestamp
                db.commit()
                self._last_seen_write_at[vehicle_id] = time.monotonic()
                logger.debug(f"Updated last_seen_v3 for vehicle '{vehicle_id}' to {timestamp} based on metric '{metric_name}'")
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error processing MQTT metric message on topic {msg.topic}: {e}", exc_info=True)

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            logger.info("MQTT Metrics Subscriber disconnected.")

mqtt_metrics_subscriber = MqttMetricsSubscriber()
