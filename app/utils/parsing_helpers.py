import math
from typing import Any, Optional, Dict
import logging

logger = logging.getLogger(__name__)

def _parse_payload_to_dict(payload_str: str, expected_min_len: int = 0) -> Dict[int, str]:
    """Converts a comma-separated payload string to a dictionary indexed by part number."""
    parts = payload_str.split(',')
    if len(parts) < expected_min_len:
        logger.warning(f"Payload '{payload_str[:30]}...' has fewer parts ({len(parts)}) than expected ({expected_min_len}).")
    return dict(enumerate(parts))

def _safe_float_parse(value: Any, default: Optional[float] = None) -> Optional[float]:
    """
    Safely parses a value to float, returning default on failure.

    Non-finite values count as failure. Python's float() happily parses "inf",
    "-inf" and "nan", so a caller guarding on `is not None` still received one —
    and `int(float("inf"))` raises OverflowError. A vehicle publishing `inf` to a
    metric that feeds int() therefore turned the state endpoint into a 500 for as
    long as the metric stayed cached, refreshable at will.
    """
    if value is None or value == '':
        return default
    try:
        parsed = float(value)
    except (ValueError, TypeError):
        return default
    if not math.isfinite(parsed):
        logger.warning(f"Rejected non-finite numeric value {parsed!r}.")
        return default
    return parsed

def _safe_truncated_int_str(value: Any, default: str = "0") -> str:
    """
    Parse a numeric value and render it as a truncated integer string.

    Exists so callers stop writing `str(int(float(v)))` guarded by a separate
    `_safe_float_parse(v) is not None`. That pattern parsed twice and did the unsafe
    conversion on the raw string, so the guard and the conversion could disagree —
    which is exactly how `inf` reached int() and raised OverflowError.
    """
    parsed = _safe_float_parse(value)
    if parsed is None:
        return default
    return str(int(parsed))


def _safe_int_parse(value: Any, default: Optional[int] = None) -> Optional[int]:
    """Safely parses a value to int, returning default on failure."""
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def _safe_get_from_list(data_list: list, index: int, default: Any = "N/A") -> Any:
    """Safely gets an item from a list by index, returning default if index is out of bounds or item is empty."""
    try:
        val = data_list[index]
        return val if val else default 
    except IndexError:
        return default

def safe_format_float_str(val_str: Any, precision: int = 1, default_val: str = "N/A") -> str:
    """Safely formats a string or number to a float string with given precision."""
    if val_str is None or val_str == "N/A" or val_str == '':
        return default_val
    try:
        return f"{float(val_str):.{precision}f}"
    except (ValueError, TypeError):
        return default_val