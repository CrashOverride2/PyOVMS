"""
Commands reach the server log by their verb only, and replies not at all.

Every admin reads the log through /admin/logs, without a support grant. It used to
carry the owner's terminal in full — `config set … password …`, the V2 `3,<param>,
<value>`, and every reply, positions included — which made both the consent of
support mode and the audit's `summarize_command` moot.
"""

import asyncio
import logging
from types import SimpleNamespace

from app.connection_manager import ConnectionManager


def test_the_v2_path_logs_neither_arguments_nor_the_reply(caplog):
    manager = ConnectionManager()

    class Car:
        authenticated = True
        addr_str = "203.0.113.5:1234"

        def __init__(self):
            self.command_futures = {}

        async def send_encrypted_message(self, code, payload):
            fut = self.command_futures["c3"]
            fut.set_result("3,0,secret-reply-at-52.52,13.40")

    car = Car()
    manager.get_car_connection = lambda vehicle_id: car

    async def scenario():
        return await manager.forward_to_car("CAR1", "3,4,s3cr3t-password", None)

    with caplog.at_level(logging.DEBUG):
        reply = asyncio.run(scenario())
    assert reply == "3,0,secret-reply-at-52.52,13.40"
    assert "s3cr3t" not in caplog.text
    assert "secret-reply" not in caplog.text
    assert "C3 " in caplog.text or "C3 from" in caplog.text


def test_the_v3_path_logs_neither_arguments_nor_the_reply(caplog):
    from app.mqtt_interactive_client import MqttInteractiveClient

    client = MqttInteractiveClient()
    loop = asyncio.new_event_loop()
    try:
        fut = loop.create_future()
        client.command_futures["abc"] = fut
        msg = SimpleNamespace(topic="ovms/u/CAR1/client/x/response/abc",
                              payload=b"Position: 52.520000,13.405000")
        with caplog.at_level(logging.DEBUG):
            client._on_message(None, None, msg)
        assert fut.result() == "Position: 52.520000,13.405000"
    finally:
        loop.close()
    assert "52.52" not in caplog.text
