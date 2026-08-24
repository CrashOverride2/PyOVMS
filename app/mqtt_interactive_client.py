import paho.mqtt.client as mqtt
import logging
import asyncio
import secrets
from typing import Dict, Optional

from app.config import settings
from app.models import api as models_api

logger = logging.getLogger(__name__)

class MqttInteractiveClient:
    """Handles interactive V3 command request/response cycles over MQTT."""

    def __init__(self):
        self._client: mqtt.Client = None
        self._is_connected = False
        self.client_id: Optional[str] = None
        self.command_futures: Dict[str, asyncio.Future] = {}

    def connect(self, username: str, password: str):
        if not all([settings.MQTT_BROKER_HOST, username, password]):
            logger.warning("MQTT Interactive Client disabled: Broker/credentials not configured.")
            return

        self.client_id = f"{settings.MQTT_INTERACTIVE_CLIENT_ID_PREFIX}_{secrets.token_hex(8)}"
        self._client = mqtt.Client(client_id=self.client_id)
        self._client.username_pw_set(username, password)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

        try:
            self._client.connect(settings.MQTT_BROKER_HOST, settings.MQTT_BROKER_PORT, 60)
            self._client.loop_start()
        except Exception as e:
            logger.error(f"MQTT Interactive Client failed to connect: {e}", exc_info=True)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"MQTT Interactive Client connected to broker as '{self.client_id}'.")
            self._is_connected = True
            topic = f"ovms/+/+/client/{self.client_id}/response/#"
            client.subscribe(topic)
            logger.info(f"MQTT Interactive Client subscribed to response topic: {topic}")
        else:
            logger.error(f"MQTT Interactive Client connection failed with code {rc}")
            self._is_connected = False

    def _on_disconnect(self, client, userdata, rc):
        logger.warning(f"MQTT Interactive Client disconnected with code {rc}.")
        self._is_connected = False
        for future in self.command_futures.values():
            if not future.done():
                future.cancel("MQTT client disconnected")
        self.command_futures.clear()

    def _on_message(self, client, userdata, msg):
        try:
            topic_parts = msg.topic.split('/')
            if len(topic_parts) == 7:
                command_id = topic_parts[-1]
                future = self.command_futures.get(command_id)
                if future and not future.done():
                    response_payload = msg.payload.decode()
                    logger.info(f"MQTT Interactive: Received response for command ID {command_id}: {response_payload}")
                    future.set_result(response_payload)
        except Exception as e:
            logger.error(f"Error processing MQTT interactive response on topic {msg.topic}: {e}", exc_info=True)

    async def send_command(self, user: str, vehicle_id: str, command: str) -> models_api.CommandResponse:
        if not self._is_connected or not self.client_id:
            return models_api.CommandResponse(vehicle_id=vehicle_id, success=False, error_message="MQTT Interactive Client is not connected.")

        command_id = secrets.token_hex(8)
        future = asyncio.get_event_loop().create_future()
        self.command_futures[command_id] = future

        topic = f"ovms/{user}/{vehicle_id}/client/{self.client_id}/command/{command_id}"

        try:
            logger.info(f"MQTT Interactive: Sending command '{command}' to topic '{topic}'")
            result = self._client.publish(topic, command)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                return models_api.CommandResponse(vehicle_id=vehicle_id, success=False, error_message=f"MQTT publish error: {mqtt.error_string(result.rc)}")

            response_data = await asyncio.wait_for(future, timeout=20.0)
            
            first_line = response_data.split('\n', 1)[0].lower()
            is_success = "failed" not in first_line and "unknown command" not in first_line and "error" not in first_line

            return models_api.CommandResponse(
                vehicle_id=vehicle_id,
                response_data=response_data,
                success=is_success
            )
        except asyncio.TimeoutError:
            logger.warning(f"MQTT Interactive: Timeout waiting for response to command ID {command_id} for vehicle {vehicle_id}")
            return models_api.CommandResponse(vehicle_id=vehicle_id, success=False, error_message="Command (V3) timed out waiting for vehicle response.")
        except asyncio.CancelledError:
            logger.info(f"MQTT Interactive: Command {command_id} to {vehicle_id} was cancelled.")
            return models_api.CommandResponse(vehicle_id=vehicle_id, success=False, error_message="Command (V3) was cancelled.")
        finally:
            self.command_futures.pop(command_id, None)

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            logger.info("MQTT Interactive Client disconnected.")

mqtt_interactive_client = MqttInteractiveClient()