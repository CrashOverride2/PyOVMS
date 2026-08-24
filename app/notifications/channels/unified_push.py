"""UnifiedPush delivery.

The endpoint is a full URL chosen by the client's distributor, so it goes through the
same SSRF guard as NTFY — restricted to https, which is what lets the pinning in
outbound.py stay a no-op here (see its docstring).
"""

import logging
from typing import Dict, Optional

from app.notifications.errors import InvalidPushTargetError, TransientDeliveryError
from app.notifications.outbound import post

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("https",)

# Status codes a distributor uses to say the endpoint has been revoked for good.
GONE_STATUS_CODES = frozenset({404, 410})


def send_unified_push_notification(endpoint_url: str, title: str, body: str, data: Optional[Dict] = None, badge: int = 0) -> bool:
    payload: Dict = {"title": title, "message": body, "badge": badge}
    if data:
        payload["data"] = data

    try:
        status_code, response_body = post(endpoint_url, json=payload, allowed_schemes=ALLOWED_SCHEMES)
    except ValueError as e:
        logger.error(f"UnifiedPush: Blocked outbound request — {e}")
        return False

    if 200 <= status_code < 300:
        logger.info(f"UnifiedPush notification sent to {endpoint_url[:40]}...")
        return True

    if status_code in GONE_STATUS_CODES:
        raise InvalidPushTargetError(f"UnifiedPush endpoint gone (HTTP {status_code})")

    if status_code == 429 or status_code >= 500:
        # The old code called raise_for_status() and the resulting HTTPError was caught
        # as a transient error only because requests' exceptions derive from OSError.
        # Now that the classification is explicit, say so explicitly.
        raise TransientDeliveryError(f"UnifiedPush endpoint returned HTTP {status_code}")

    logger.error(
        f"UnifiedPush endpoint {endpoint_url[:40]}... returned HTTP {status_code}. "
        f"Will not retry. Response: {response_body}"
    )
    return False
