"""
Step-up re-authentication for actions that change how an account can be entered.

`verify_password` had exactly three call sites in the whole repo — the login and the
two password changes. Everything else ran on the session alone: disabling TOTP,
registering a WebAuthn credential, deleting one, creating an API key, changing the
e-mail address, deleting the account.

The chain that made this worth fixing: brief access to a logged-in session is enough
to register a passkey with `usage_mode='passwordless'`. That is a permanent second
way in, it does not depend on the password, and it survives a password change. The
owner only notices if they happen to open the WebAuthn tab.

The rule here is deliberately coarse — "was a password proved recently?" — rather
than a per-action token. One marker, one window, one helper, so a new sensitive route
gets it by importing rather than by re-implementing.

Freshness is stored in the session cookie, which is signed by SECRET_KEY_SESSION and
cannot be forged client-side. It is bound to the user id so a session that somehow
changes hands cannot inherit the other account's freshness.
"""

import time
from typing import Optional

from fastapi import Request

# How long a proven password stays good for. Long enough to complete a settings
# visit without re-typing, short enough that a walk-away session goes cold.
STEP_UP_WINDOW_SECONDS = 300

_SESSION_KEY = "step_up_at"
_SESSION_USER_KEY = "step_up_user_id"


def mark_reauthenticated(request: Request, user_id: int) -> None:
    """Record that this user just proved their password."""
    request.session[_SESSION_KEY] = time.time()
    request.session[_SESSION_USER_KEY] = user_id


def clear_reauthentication(request: Request) -> None:
    request.session.pop(_SESSION_KEY, None)
    request.session.pop(_SESSION_USER_KEY, None)


def has_recent_reauth(request: Request, user_id: int) -> bool:
    """
    True if this user proved their password within the window.

    Checks the user id as well as the timestamp: the marker is meaningless — and
    dangerous — if it is read on behalf of a different account than the one that set
    it.
    """
    marked_user = request.session.get(_SESSION_USER_KEY)
    marked_at: Optional[float] = request.session.get(_SESSION_KEY)

    if marked_user != user_id or not isinstance(marked_at, (int, float)):
        return False
    # A timestamp in the future means a tampered or clock-skewed value; treat it as
    # absent rather than as indefinitely valid.
    age = time.time() - marked_at
    return 0 <= age <= STEP_UP_WINDOW_SECONDS


def seconds_remaining(request: Request, user_id: int) -> int:
    if not has_recent_reauth(request, user_id):
        return 0
    return int(STEP_UP_WINDOW_SECONDS - (time.time() - request.session[_SESSION_KEY]))
