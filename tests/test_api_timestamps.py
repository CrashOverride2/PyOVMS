"""
Every timestamp the JSON API emits carries its zone.

`DateTime(timezone=True)` reads back tz-aware on PostgreSQL and naive on SQLite, and
Pydantic serialises whatever it was handed. A bare `datetime.datetime` annotation
therefore emits `2026-03-04T05:06:07` on one deployment and `...Z` on another, from
identical code. Both halves are UTC; only one says so.

That is not a cosmetic difference. A client reading the unmarked half applies its own
zone — Dart's `DateTime.parse` treats a string with no designator as local time, so the
Flutter app's `.toLocal()` became a no-op and every stamp was displayed off by the UTC
offset. Silently, and only on SQLite deployments, which is why it survived so long.

`UtcDatetime` is the fix; the static test at the bottom is what keeps it applied.
"""

import ast
import datetime
import pathlib
import re

import pytest

from app.models import api as models_api
from app.utils.timestamps import as_utc

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "app"

# A response model is any Pydantic model reachable from a route, and they are not all in
# app/models/api.py: the security-events, device-token and charge-logger routers declare
# their own. Scanning only the one file is how three of them kept a bare datetime through
# the change that fixed the rest, so the scan follows the base class instead of the path.
BASE_CLASSES = {"BaseModel"}

# `datetime.datetime`, a bare `datetime` (from `from datetime import datetime`), or the
# alias itself. Deliberately not `datetime.date`: a calendar date names no instant, so it
# has no zone to lose — ChargeStatisticsMonthly.period is a month label, not a time.
_DATETIME_ANNOTATION = re.compile(r"\bdatetime\.datetime\b|\bUtcDatetime\b|(?<!\.)\bdatetime\b(?!\.)")

# The naive stamp is the subject of the test, not an oversight: it stands for what
# SQLite reads back out of a `DateTime(timezone=True)` column, which is exactly the
# input `as_utc` exists to label. Giving it a tzinfo would test nothing.
NAIVE = datetime.datetime(2026, 3, 4, 5, 6, 7, 123456)  # noqa: DTZ001
AWARE = NAIVE.replace(tzinfo=datetime.timezone.utc)
OFFSET = NAIVE.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=2)))


# --- the value normalisation ------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (NAIVE, AWARE),
    (AWARE, AWARE),
    # A wall clock two hours ahead names an instant two hours earlier in UTC.
    (OFFSET, NAIVE.replace(hour=3, tzinfo=datetime.timezone.utc)),
])
def test_as_utc_labels_or_converts(value, expected):
    assert as_utc(value) == expected
    assert as_utc(value).tzinfo is datetime.timezone.utc


def test_as_utc_passes_none_through():
    """"No records yet" is not a time, and must not become the epoch."""
    assert as_utc(None) is None


# --- what actually goes on the wire -----------------------------------------------

def test_a_naive_value_is_still_serialised_with_its_zone():
    """The SQLite case. Before UtcDatetime this emitted no designator at all."""
    payload = models_api.PushSubscriptionInfo(
        id=1, push_type="email", device_id="a@example.com",
        endpoint="a@example.com", created_at=NAIVE,
    ).model_dump_json()

    assert '"created_at":"2026-03-04T05:06:07.123456Z"' in payload


def test_an_absent_timestamp_stays_null():
    payload = models_api.DataLogTypeInfo(record_type="*-LOG-Trip").model_dump_json()

    assert '"first":null' in payload
    assert '"last":null' in payload


def test_a_postgres_style_aware_value_is_unchanged():
    payload = models_api.DataLogRecord(timestamp=AWARE).model_dump_json()

    assert '"timestamp":"2026-03-04T05:06:07.123456Z"' in payload


# --- the guard that outlives this change ------------------------------------------

def _model_bases(tree):
    """Class names in this module that ultimately derive from BaseModel."""
    models = set(BASE_CLASSES)
    # Two passes: a subclass may be defined before the model it extends is seen.
    for _ in range(2):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                isinstance(b, ast.Name) and b.id in models for b in node.bases
            ):
                models.add(node.name)
    return models


def _datetime_fields():
    """Every Pydantic model field under app/ annotated as a datetime.

    Read from the source rather than from the imported classes: `UtcDatetime` is an
    Annotated alias, and at runtime it is indistinguishable enough from a plain
    datetime that a check on the live model would keep passing after someone typed
    the bare one.
    """
    for path in sorted(APP_DIR.rglob("*.py")):
        source = path.read_text()
        if "BaseModel" not in source:
            continue
        tree = ast.parse(source, filename=str(path))
        models = _model_bases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name not in models:
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                    continue
                annotation = ast.unparse(stmt.annotation)
                if _DATETIME_ANNOTATION.search(annotation):
                    yield (f"{path.relative_to(REPO_ROOT)}::{node.name}",
                           stmt.target.id, annotation)


ALL_DATETIME_FIELDS = list(_datetime_fields())


def test_the_scan_still_finds_the_fields_it_guards():
    """A guard whose subject silently becomes an empty set passes forever."""
    assert len(ALL_DATETIME_FIELDS) >= 20, (
        f"only {len(ALL_DATETIME_FIELDS)} datetime fields found under app/ — "
        "the scan has stopped matching how they are declared."
    )


def test_no_api_model_declares_a_bare_datetime():
    offenders = [
        f"{cls}.{field}: {annotation}"
        for cls, field, annotation in ALL_DATETIME_FIELDS
        if "UtcDatetime" not in annotation
    ]
    assert offenders == [], (
        "these fields serialise without a zone designator on SQLite and with one on "
        "PostgreSQL, so a client cannot tell what the value means. Annotate them "
        "UtcDatetime (app/utils/timestamps.py): " + ", ".join(offenders)
    )
