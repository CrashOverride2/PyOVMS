"""The owner's open browser tabs.

Not a channel in the dispatcher's sense: there is no target to resolve, nothing to
retry and nothing that can be permanently gone. A notification is handed to the
WebSocket manager's `user:<owner>` topic, and whichever of the owner's tabs is
subscribed renders it as a toast — or, if the tab is hidden and the person opted in,
as a native browser notification. Nobody subscribed means nothing happens.

This runs on the dispatcher's worker thread, so it goes through
`broadcast_threadsafe()`, which never blocks and never raises.
"""

import logging
import secrets
from typing import Dict, Optional

from app.websocket_manager import USER_TOPIC_ALIAS, manager as websocket_manager, user_topic

logger = logging.getLogger(__name__)

# The V2 'P' frame's type character (and the V3 topic mapped onto it). 'F' is a firmware
# note and informational. The client renders `alert` and `error` the same way (red,
# sticky); the payload keeps them apart so nothing has to be re-mapped later.
SEVERITY_BY_ALERT_TYPE = {'I': 'info', 'W': 'warn', 'A': 'alert', 'E': 'error', 'F': 'info'}
DEFAULT_SEVERITY = 'info'


def severity_for(alert_type_char: Optional[str]) -> str:
    return SEVERITY_BY_ALERT_TYPE.get((alert_type_char or '').upper(), DEFAULT_SEVERITY)


def build_web_notification(
    *,
    vehicle_id: str,
    title: str,
    body: str,
    alert_type_char: Optional[str],
    source_protocol: str,
    subtype: str,
    timestamp: str,
) -> dict:
    """The payload one tab renders. Pure; the id is what lets several tabs deduplicate."""
    return {
        "id": secrets.token_hex(8),
        "vehicle_id": vehicle_id,
        "title": title,
        "body": body,
        "severity": severity_for(alert_type_char),
        "subtype": subtype,
        "source_protocol": source_protocol,
        "timestamp": timestamp,
    }


def notify_owner_browser(
    owner_id: Optional[int],
    *,
    vehicle_id: str,
    title: str,
    body: str,
    alert_type_char: Optional[str],
    source_protocol: str,
    fcm_data_payload: Optional[Dict[str, str]],
    timestamp: str,
) -> bool:
    """
    Schedule the notification for the owner's subscribed tabs. True means scheduled.

    Fire-and-forget by design: it is called before the push channels send, and a
    failure here must not cost the phone its notification. The subtype is whatever the
    protocol handler put into the push payload — `v3_subtype` for MQTT, `notification_id`
    for a V2 frame — so the toast can say "charge/done" without a third parser.

    Routed on `user:<owner id>`, tagged `user:me`: the page keys its handlers on the
    topic string it subscribed with, and it only ever knows its own topic by that
    alias. Tagged with the routing key, the frame arrived and was dropped unrendered.
    """
    if owner_id is None:
        return False
    try:
        data = fcm_data_payload or {}
        subtype = data.get("v3_subtype") or data.get("notification_id") or ""
        payload = build_web_notification(
            vehicle_id=vehicle_id,
            title=title,
            body=body,
            alert_type_char=alert_type_char,
            source_protocol=source_protocol,
            subtype=subtype,
            timestamp=timestamp,
        )
        return websocket_manager.broadcast_threadsafe(
            user_topic(owner_id), {"topic": USER_TOPIC_ALIAS, "type": "notification", "payload": payload}
        )
    except Exception as e:
        logger.debug(f"Browser notification for {vehicle_id} not scheduled: {e}")
        return False
