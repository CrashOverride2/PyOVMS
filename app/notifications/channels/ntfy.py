"""NTFY delivery.

The server URL, the topic and the credentials are all per-vehicle and user-supplied,
which is what makes this the most exposed channel in the subsystem: the request carries
the user's own NTFY token, and the URL is assembled from values they control.
"""

import base64
import logging
import re
from typing import List, Optional
from urllib.parse import urlencode

from app.config import settings
from app.notifications.errors import TransientDeliveryError
from app.notifications.outbound import post
from app.utils.email_validation import sanitize_header_value

logger = logging.getLogger(__name__)

# Validating this is not cosmetic. The topic is concatenated into the request path, so a
# value like '../../v1/account/settings' or 'topic?x=1' sends the *user's bearer token*
# to a different endpoint on their NTFY server than the one they meant to publish to.
#
# The leading lookahead is what rejects '.' and '..'. Excluding '/' already bounds the
# damage to a single path segment, but '..' still resolves to the server root, and a
# topic that is nothing but dots cannot be a topic anyone meant — so require at least
# one alphanumeric character rather than reasoning about what a given server does with
# a dot segment.
#
# Otherwise the check is about characters, not length: the length bound is the storage
# column (Vehicle.ntfy_topic is String(100)), deliberately not NTFY's own 64, so that
# upgrading cannot start refusing a topic that this server previously accepted and
# stored. NTFY's own rule is [-_A-Za-z0-9]{1,64} and it enforces that itself; '.' is
# tolerated here because topics generated from vehicle ids have historically contained
# one.
_TOPIC_RE = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9_.-]{1,100}$")

# NTFY rejects priorities outside 1..5 with a 400; clamping keeps a bad value from
# turning into a delivery failure.
_MIN_PRIORITY, _MAX_PRIORITY = 1, 5

_EMOJI_TAG_CHARS = frozenset("IAWEF")


def send_ntfy_notification(
    topic: str,
    title: str,
    message: str,
    priority: int = 3,
    tags: Optional[List[str]] = None,
    server_url: Optional[str] = None,
    auth_method: Optional[str] = None,
    auth_token: Optional[str] = None,
    auth_user: Optional[str] = None,
    auth_password: Optional[str] = None,
    auth_query_param_name: Optional[str] = None,
) -> bool:

    ntfy_server_to_use = server_url or settings.NTFY_SERVER
    # Surrounding slashes were previously stripped when the URL was assembled, so stored
    # topics may still carry them; strip before validating rather than rejecting those.
    actual_topic_to_use = (topic or "").strip().strip("/")
    auth_method_to_use = auth_method if auth_method is not None else settings.NTFY_AUTH_METHOD
    auth_token_to_use = auth_token if auth_token is not None else settings.NTFY_AUTH_TOKEN
    auth_user_to_use = auth_user if auth_user is not None else settings.NTFY_AUTH_USER
    auth_password_to_use = auth_password if auth_password is not None else settings.NTFY_AUTH_PASSWORD
    auth_query_param_name_to_use = auth_query_param_name if auth_query_param_name is not None else settings.NTFY_AUTH_QUERY_PARAM_NAME

    if not ntfy_server_to_use:
        logger.warning("NTFY server (resolved) not configured. Skipping NTFY notification.")
        return False
    if not actual_topic_to_use:
        logger.warning("NTFY topic (resolved) is empty. Skipping NTFY notification.")
        return False
    if not _TOPIC_RE.match(actual_topic_to_use):
        logger.error(
            "NTFY topic %r is not a valid topic name; refusing to send. Allowed "
            "characters: letters, digits, '.', '_' and '-' (max 100), and at least "
            "one letter or digit.",
            actual_topic_to_use[:80],
        )
        return False

    url = f"{ntfy_server_to_use.rstrip('/')}/{actual_topic_to_use}"

    try:
        encoded_title_for_header = title.encode('utf-8').decode('latin-1', 'surrogateescape')
    except UnicodeEncodeError:
        logger.warning(f"Could not encode title '{title}' for NTFY header, using plain ascii version.")
        encoded_title_for_header = title.encode('ascii', 'replace').decode('ascii')

    # sanitize_header_value on every header we build from message data.
    #
    # The title comes from the vehicle's notification text and the tags from the
    # topic. The e-mail path already ran them through this helper; the NTFY path did
    # not, so a CR/LF in either could append headers to the request that carries the
    # user's NTFY auth token.
    headers = {
        "Title": sanitize_header_value(encoded_title_for_header),
        "Priority": str(max(_MIN_PRIORITY, min(_MAX_PRIORITY, int(priority)))),
        "Markdown": "yes",
    }
    if tags:
        safe_tags = [sanitize_header_value(t).replace(",", " ") for t in tags]
        safe_tags = [t for t in safe_tags if t]
        emoji_tag = next((tag for tag in safe_tags if len(tag) == 1 and tag.upper() in _EMOJI_TAG_CHARS), None)
        if safe_tags:
            if emoji_tag:
                headers["Tags"] = ",".join(safe_tags) + f",{emoji_tag.lower()}"
            else:
                headers["Tags"] = ",".join(safe_tags)

    query_params = None
    if auth_method_to_use and auth_method_to_use.lower() != "none":
        method = auth_method_to_use.lower()
        if method == "bearer" and auth_token_to_use:
            headers["Authorization"] = f"Bearer {auth_token_to_use}"
        elif method == "basic" and auth_user_to_use and auth_password_to_use:
            user_pass = f"{auth_user_to_use}:{auth_password_to_use}"
            basic_auth_token = base64.b64encode(user_pass.encode()).decode()
            headers["Authorization"] = f"Basic {basic_auth_token}"
        elif method == "query" and auth_token_to_use:
            param_name = auth_query_param_name_to_use or "token"
            separator = "&" if "?" in url else "?"
            query_params = separator + urlencode({param_name: auth_token_to_use})

    if query_params:
        url += query_params

    try:
        status_code, body = post(url, headers=headers, data=message.encode("utf-8"))
    except ValueError as e:
        logger.error(f"NTFY: Blocked outbound request — {e}")
        return False

    if status_code == 200:
        logger.info(f"NTFY notification sent to {actual_topic_to_use} on {ntfy_server_to_use}: '{title}'")
        return True

    if status_code == 429 or status_code >= 500:
        # Public NTFY instances rate-limit with 429 and the backoff is exactly the right
        # answer. Previously any non-200 was a permanent failure and the message was lost.
        #
        # Raised rather than retried here: the dispatcher classifies this and hands it to
        # the retry scheduler, so the wait costs a heap entry instead of the worker thread
        # this call is running on.
        raise TransientDeliveryError(
            f"NTFY server {ntfy_server_to_use} returned HTTP {status_code}"
        )

    logger.error(
        f"NTFY: Failed to send to {actual_topic_to_use} on {ntfy_server_to_use}. "
        f"Status: {status_code}, Response: {body}"
    )
    return False
