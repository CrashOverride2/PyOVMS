"""
The iOS app's Notification Service Extension only runs for a push whose `aps` carries
`"mutable-content": 1` — it masks a SIM PIN in the text and records the push for the
app's history. Every *visible* iOS push therefore carries it, on both delivery paths
(direct APNs, and APNs tunnelled through FCM), and nothing else does: Android FCM has no
use for it, and on a silent push (no alert) it is meaningless.

The extension reads the data keys (vehicle_id, timestamp, notification_type, ...) at the
top level of the APNs userInfo, so they must stay there and not move into `aps`.

Both senders are exercised for real, down to the bytes they would hand to the transport:
the direct client is replaced by a recorder, and the FCM message is run through
firebase_admin's own encoder.
"""

import json
import time
from pathlib import Path

import pytest
from firebase_admin import messaging

from app.notifications.channels import apns as apns_channel
from app.notifications.channels import fcm as fcm_channel

REPO_ROOT = Path(__file__).resolve().parent.parent

DATA = {
    "vehicle_id": "CAR1",
    "timestamp": "2026-10-03T12:00:00Z",
    "notification_type": "alert",
    "v3_subtype": "charge.stopped",
}


# ---------------------------------------------------------------------------
# direct APNs
# ---------------------------------------------------------------------------

class _RecordingApnsClient:
    def __init__(self):
        self.sent = []
        self.options = []

    def send(self, device_token, payload, topic=None, **options):
        self.sent.append((device_token, payload, topic))
        self.options.append(options)


@pytest.fixture
def apns_client(monkeypatch):
    client = _RecordingApnsClient()
    monkeypatch.setattr(apns_channel, "_apns_client", client)
    return client


def test_direct_apns_alert_is_mutable(apns_client):
    assert apns_channel.send_apns_notification("tok-123", "Battery low", "SOC 12%", data=DATA, badge=3)

    (_token, payload, _topic), = apns_client.sent
    aps = payload["aps"]
    assert aps["mutable-content"] == 1
    assert aps["alert"] == {"title": "Battery low", "body": "SOC 12%"}
    assert aps["badge"] == 3


def test_direct_apns_alert_is_kept_for_an_unreachable_device(apns_client):
    """The client's default `apns-expiration` is 0: one attempt, nothing stored. An
    iPhone without reception at that moment would never see the alert, and the
    extension would never file it for the history. Only the badge reset wants that."""
    before = int(time.time())
    apns_channel.send_apns_notification("tok-123", "t", "b", data=DATA)

    (options,) = apns_client.options
    lifetime = options["expiration"] - before
    assert apns_channel.APNS_ALERT_LIFETIME_SECONDS - 5 <= lifetime <= apns_channel.APNS_ALERT_LIFETIME_SECONDS + 5
    assert lifetime > 0


def test_direct_apns_keeps_data_keys_at_top_level(apns_client):
    apns_channel.send_apns_notification("tok-123", "t", "b", data=DATA)

    (_token, payload, _topic), = apns_client.sent
    for key, value in DATA.items():
        assert payload[key] == value
        assert key not in payload["aps"]


# ---------------------------------------------------------------------------
# FCM (Android, and APNs tunnelled through it)
# ---------------------------------------------------------------------------

@pytest.fixture
def fcm_sent(monkeypatch):
    sent = []
    monkeypatch.setattr(fcm_channel, "_firebase_app_initialized", True)

    def _send(message, *args, **kwargs):
        # The wire form, exactly as firebase_admin would POST it.
        sent.append(json.loads(json.dumps(message, cls=messaging._messaging_encoder.MessageEncoder)))
        return "projects/test/messages/1"

    monkeypatch.setattr(fcm_channel.messaging, "send", _send)
    return sent


def test_apns_via_fcm_alert_is_mutable(fcm_sent):
    assert fcm_channel.send_fcm_notification(
        "tok-ios", "Battery low", "SOC 12%", data=DATA, is_apns_token=True, badge=5
    )

    (wire,) = fcm_sent
    payload = wire["apns"]["payload"]
    aps = payload["aps"]
    assert aps["mutable-content"] == 1
    assert aps["badge"] == 5, "the badge is the dispatcher's, not a hard-coded 1"
    assert aps["alert"] == {"title": "Battery low", "body": "SOC 12%"}
    for key, value in DATA.items():
        assert payload[key] == value
        assert key not in aps


def test_plain_fcm_carries_an_ios_override(fcm_sent):
    """The app registers iPhones as push_type 'fcm' too, so the plain FCM message has to
    carry what an iPhone needs: FCM applies the apns block for an APNs-backed token."""
    assert fcm_channel.send_fcm_notification("tok-any", "Battery low", "SOC 12%", data=DATA, badge=4)

    (wire,) = fcm_sent
    payload = wire["apns"]["payload"]
    assert payload == {
        "aps": {
            "alert": {"title": "Battery low", "body": "SOC 12%"},
            "sound": "default",
            "badge": 4,
            "mutable-content": 1,
        }
    }, "only aps belongs here: the data keys reach the userInfo's top level via message.data"
    assert wire["data"] == DATA


def test_plain_fcm_android_part_is_unchanged_apart_from_the_count(fcm_sent):
    assert fcm_channel.send_fcm_notification("tok-android", "Battery low", "SOC 12%", data=DATA, badge=4)

    (wire,) = fcm_sent
    assert wire["notification"] == {"title": "Battery low", "body": "SOC 12%"}
    assert wire["data"] == DATA
    assert wire["android"] == {"notification": {"notification_count": 4}}
    assert "mutable-content" not in json.dumps({k: v for k, v in wire.items() if k != "apns"})


# ---------------------------------------------------------------------------
# silent pushes
# ---------------------------------------------------------------------------

def test_mutable_content_is_set_only_by_the_alert_senders():
    """
    mutable-content needs an alert. The two alert senders are the only places allowed to
    set it; a silent push added elsewhere must not copy it. The badge reset is one
    (`send_*_badge_reset`, pinned in test_badge_reset.py) — it lives in the same two
    files, so its own test checks that it carries none.
    """
    allowed = {
        REPO_ROOT / "app" / "notifications" / "channels" / "apns.py",
        REPO_ROOT / "app" / "notifications" / "channels" / "fcm.py",
    }
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in (REPO_ROOT / "app").rglob("*.py")
        if path not in allowed
        and ("mutable-content" in (text := path.read_text(encoding="utf-8")) or "mutable_content" in text)
    ]
    assert offenders == []
