"""Helpers for validating e-mail addresses and header values before they reach SMTP.

Notification recipients are user-supplied (vehicle `notification_email`, manually
added e-mail push subscriptions) and notification subjects are partly *vehicle*
supplied. Python's default `compat32` e-mail policy happily serialises a header
containing CR/LF, so an unchecked value lets the submitter append arbitrary
headers — extra `Bcc:` recipients, a forged `From:`, or a second message body —
turning the server into an open relay for spam sent from its own domain.
"""

import re
from typing import Optional

# Deliberately stricter than RFC 5322: no quoted local parts, no comments, no
# display names. Notification recipients are plain addresses, and every exotic
# form the RFC permits is a way to smuggle something past a naive check.
_ADDRESS_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

# CR and LF terminate a header; NUL truncates it in some MTAs. Checked
# separately from the pattern above so the error message can be specific.
_FORBIDDEN_IN_HEADER = ("\r", "\n", "\0")

MAX_EMAIL_LENGTH = 255


class InvalidEmailAddress(ValueError):
    """Raised when an address is unusable or would inject e-mail headers."""


def validate_email_address(value: str) -> str:
    """
    Return the address unchanged if it is a single, safe RFC address.

    Raises InvalidEmailAddress otherwise. Surrounding whitespace is stripped
    first; anything else that is not part of a bare address is a hard error
    rather than something to sanitise away.
    """
    if value is None:
        raise InvalidEmailAddress("E-mail address is missing.")

    candidate = value.strip()

    if not candidate:
        raise InvalidEmailAddress("E-mail address is empty.")
    if len(candidate) > MAX_EMAIL_LENGTH:
        raise InvalidEmailAddress(f"E-mail address exceeds {MAX_EMAIL_LENGTH} characters.")
    if any(ch in candidate for ch in _FORBIDDEN_IN_HEADER):
        raise InvalidEmailAddress("E-mail address must not contain line breaks or NUL bytes.")
    if "," in candidate or ";" in candidate:
        raise InvalidEmailAddress("Only a single e-mail address is allowed.")
    if not _ADDRESS_RE.match(candidate):
        raise InvalidEmailAddress("E-mail address is not a valid address.")

    return candidate


def validate_optional_email_address(value: Optional[str]) -> Optional[str]:
    """
    Validate an optional address field.

    None and the empty string mean "not configured" and pass through untouched;
    everything else must be a valid address.
    """
    if value is None:
        return None
    if not value.strip():
        return value
    return validate_email_address(value)


def sanitize_header_value(value: str) -> str:
    """
    Make an arbitrary string safe to use as a single-line header value.

    Used for subjects, which can originate from vehicle-supplied notification
    text. Unlike addresses these are free-form, so folding whitespace into
    spaces is the right call rather than rejecting the message outright.
    """
    if not value:
        return ""
    collapsed = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    return collapsed.replace("\0", "").strip()
