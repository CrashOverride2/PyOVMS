import logging
import time

from sqlalchemy.orm import Session

from app import crud

logger = logging.getLogger(__name__)

# History records (data notifications) of these record types are NOT stored in the
# historical_data table, regardless of the protocol they arrive on (V2 'h'/'H' messages
# or V3 notify/data). Override via the system setting below (comma separated list).
# GPS track logs are excluded by default: Karto consumes them for the trip routes, and at
# one record every few seconds they would displace the valuable session logs from the
# per-vehicle row quota.
# The setting key keeps its historical "v3_" prefix for compatibility with existing
# deployments, although the blocklist applies to both protocols.
DATA_RECORD_BLOCKLIST_KEY = "v3_data_record_blocklist"
DATA_RECORD_BLOCKLIST_DEFAULT = "XNE-GPS-Log,RT-GPS-Log"

_CACHE_TTL_SECONDS = 60.0
_cache: tuple[float, set] = (0.0, set())


def get_record_blocklist(db: Session) -> set:
    """Record types excluded from generic storage, from the system settings (cached).
    The session is only used on a cache miss and is not closed here."""
    global _cache
    now = time.time()
    cached_at, blocklist = _cache
    if now - cached_at < _CACHE_TTL_SECONDS:
        return blocklist

    value = DATA_RECORD_BLOCKLIST_DEFAULT
    try:
        setting = crud.system_setting.get_setting(db, DATA_RECORD_BLOCKLIST_KEY)
        if setting is not None and setting.value is not None:
            value = setting.value
    except Exception as e:
        logger.error(f"Failed to read data record blocklist setting: {e}")

    blocklist = {t.strip() for t in value.split(',') if t.strip()}
    _cache = (now, blocklist)
    return blocklist
