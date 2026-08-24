"""Exception types shared by every notification channel.

Kept in a leaf module so the channels, the retry policy and the dispatcher can
all import them without importing each other.
"""


class NotificationError(Exception):
    """Base class for notification delivery failures."""


class InvalidPushTargetError(NotificationError):
    """The push target (device token / endpoint) is permanently invalid.

    Raised by the channel senders instead of retrying; the dispatcher reacts by
    removing the dead per-device subscription so the target is not tried again.
    """


class TransientDeliveryError(NotificationError):
    """The far end failed in a way a later attempt may get past (5xx, 429).

    Exists so an HTTP-level temporary failure can be classified by retry.is_transient()
    without dressing it up as a transport exception.
    """


class OutboundBlockedError(NotificationError, ValueError):
    """An outbound URL was refused by the SSRF guard.

    Derives from ValueError so the pre-existing `except ValueError` call sites — and
    the tests that assert on them — keep working unchanged.
    """
