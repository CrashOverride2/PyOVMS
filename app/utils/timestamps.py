"""
Timestamp normalisation shared by the storage layer and the JSON API.

One function, because the mistake it prevents is easy to make in either place and
invisible until a client in a non-UTC zone reads the result.
"""

import datetime
from typing import Annotated, Optional

from pydantic import PlainSerializer


def as_utc(value: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    """Tag a stored timestamp as UTC.

    SQLite has no timezone type, so a DateTime(timezone=True) column reads back naive
    there and tz-aware on PostgreSQL — the same row, the same code, two shapes. Every
    timestamp this server writes is UTC, so the naive case is a missing label rather
    than an unknown zone; but a client receiving the unlabelled half cannot know that
    and will apply its own, which is how a charge session recorded at 14:00 UTC shows
    up as 14:00 local on a phone two zones away.

    None passes through: "no records yet" is not a time.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def as_utc_iso(value: Optional[datetime.datetime]) -> Optional[str]:
    """`as_utc()` as the `...Z` string a page hands to `new Date()`.

    `isoformat() + "Z"` looked right on SQLite, where the column reads back naive; on
    PostgreSQL the same column is tz-aware and the result was `...+00:00Z`, which
    `Date.parse` rejects — every "last seen" on the dashboard read "Never" there.
    """
    utc = as_utc(value)
    if utc is None:
        return None
    return utc.isoformat().replace("+00:00", "Z")


# The API's datetime type. Use this in a response model, never a bare
# `datetime.datetime`.
#
# Pydantic serialises whatever SQLAlchemy handed it, and `DateTime(timezone=True)`
# reads back tz-aware on PostgreSQL and naive on SQLite. A bare annotation therefore
# emits `2026-03-04T05:06:07` on one deployment and `...Z` on another, from the same
# code — and a client that receives the unmarked half applies its own zone to a value
# that was always UTC. The Flutter app's `DateTime.parse(...).toLocal()` did exactly
# that, silently, for as long as the server ran on SQLite.
#
# Normalising the *value* rather than formatting a string keeps Pydantic's own encoder
# in charge, so the wire format stays `...Z` and `None` stays `null`.
UtcDatetime = Annotated[
    datetime.datetime,
    PlainSerializer(as_utc, return_type=datetime.datetime),
]
