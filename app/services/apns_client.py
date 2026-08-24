"""Minimal APNs provider client speaking Apple's HTTP/2 API directly.

Replaces apns2-plus, which pulls in `hyper` — an HTTP/2 library whose last
release predates Python 3.10 and which only imports at all because run.py used
to patch `collections`. Apple's provider API is a single JSON POST per device,
so talking to it directly costs less than keeping that stack alive.

Reference: Apple, "Sending notification requests to APNs".
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import jwt as pyjwt

from app.config import settings

logger = logging.getLogger(__name__)

PRODUCTION_HOST = "https://api.push.apple.com"
SANDBOX_HOST = "https://api.sandbox.push.apple.com"

# Apple rejects provider tokens older than one hour and refuses refreshes more
# often than every 20 minutes. 45 minutes sits comfortably between the two.
TOKEN_LIFETIME_SECONDS = 45 * 60

# Reasons that mean the device token will never work again — the caller should
# drop the subscription instead of retrying.
DEAD_TOKEN_REASONS = frozenset({
    "BadDeviceToken",
    "Unregistered",
    "DeviceTokenNotForTopic",
    "TopicDisallowed",
})


class ApnsError(Exception):
    """APNs rejected the notification for a non-recoverable reason."""


class ApnsInvalidTokenError(ApnsError):
    """The device token is permanently invalid (unregistered, wrong topic, ...)."""


class ApnsTransientError(ApnsError):
    """Temporary failure (network, throttling, APNs outage) — retrying is sensible."""


class ApnsClient:
    """Thread-safe APNs sender with a cached provider token and pooled HTTP/2 connection."""

    def __init__(self, auth_key_path: str, key_id: str, team_id: str, use_sandbox: bool = False):
        self._auth_key = Path(auth_key_path).read_text(encoding="utf-8")
        self._key_id = key_id
        self._team_id = team_id
        self.host = SANDBOX_HOST if use_sandbox else PRODUCTION_HOST

        self._token: Optional[str] = None
        self._token_issued_at: float = 0.0
        self._token_lock = threading.Lock()

        self._client = httpx.Client(
            http2=True,
            base_url=self.host,
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0),
        )

    def _provider_token(self) -> str:
        with self._token_lock:
            now = time.time()
            if self._token is None or (now - self._token_issued_at) >= TOKEN_LIFETIME_SECONDS:
                self._token = pyjwt.encode(
                    {"iss": self._team_id, "iat": int(now)},
                    self._auth_key,
                    algorithm="ES256",
                    headers={"kid": self._key_id},
                )
                self._token_issued_at = now
                logger.debug("APNs: issued a new provider token.")
            return self._token

    def send(
        self,
        device_token: str,
        payload: Dict[str, Any],
        topic: str,
        push_type: str = "alert",
        priority: int = 10,
        expiration: int = 0,
    ) -> None:
        """Delivers one notification. Raises on failure, returns None on success."""
        headers = {
            "authorization": f"bearer {self._provider_token()}",
            "apns-topic": topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
            "apns-expiration": str(expiration),
        }
        try:
            response = self._client.post(f"/3/device/{device_token}", headers=headers, json=payload)
        except httpx.HTTPError as e:
            raise ApnsTransientError(f"APNs request failed: {e}") from e

        if response.status_code == 200:
            return

        reason = ""
        try:
            reason = response.json().get("reason", "")
        except (json.JSONDecodeError, ValueError):
            reason = response.text[:200]

        if response.status_code == 410 or reason in DEAD_TOKEN_REASONS:
            raise ApnsInvalidTokenError(f"APNs rejected the device token: {reason or response.status_code}")
        if response.status_code == 403 and reason in ("ExpiredProviderToken", "InvalidProviderToken"):
            # Force a fresh token on the next attempt, then let the caller retry.
            with self._token_lock:
                self._token = None
            raise ApnsTransientError(f"APNs provider token rejected: {reason}")
        if response.status_code in (429, 500, 503):
            raise ApnsTransientError(f"APNs temporarily unavailable (HTTP {response.status_code}, {reason})")

        raise ApnsError(f"APNs rejected the notification (HTTP {response.status_code}, {reason})")

    def close(self) -> None:
        self._client.close()


def build_client_from_settings() -> Optional[ApnsClient]:
    """Creates the client if APNs is fully configured, otherwise returns None."""
    if not all([settings.APNS_AUTH_KEY_PATH, settings.APNS_KEY_ID, settings.APNS_TEAM_ID, settings.APNS_TOPIC]):
        logger.info("APNs settings not fully configured (KEY_PATH, KEY_ID, TEAM_ID, TOPIC). APNs disabled.")
        return None

    key_path = Path(settings.APNS_AUTH_KEY_PATH)
    if not key_path.exists():
        logger.warning(f"APNS_AUTH_KEY_PATH ('{key_path}') does not exist. APNs notifications disabled.")
        return None

    use_sandbox = settings.APNS_SERVER_MODE == "development"
    try:
        client = ApnsClient(
            auth_key_path=str(key_path),
            key_id=settings.APNS_KEY_ID,
            team_id=settings.APNS_TEAM_ID,
            use_sandbox=use_sandbox,
        )
    except Exception as e:
        logger.error(f"Failed to initialize APNs client: {e}", exc_info=True)
        return None

    logger.info(f"APNs client initialized for {'sandbox' if use_sandbox else 'production'} mode.")
    return client
