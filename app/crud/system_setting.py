from sqlalchemy.orm import Session
from typing import Optional, Dict, List

from app.models import db as models_db

INFO_BOX_ENABLED_KEY = "info_box_enabled"
INFO_BOX_CONTENT_KEY = "info_box_content"
INFO_BOX_TITLE_KEY = "info_box_title"
INFO_BOX_TYPE_KEY = "info_box_type"

def get_setting(db: Session, key: str) -> Optional[models_db.SystemSetting]:
    return db.query(models_db.SystemSetting).filter(models_db.SystemSetting.key == key).first()

def get_settings_map(db: Session, keys: List[str]) -> Dict[str, Optional[models_db.SystemSetting]]:
    """Return a mapping of key -> SystemSetting for the provided keys."""
    if not keys:
        return {}
    records = db.query(models_db.SystemSetting).filter(models_db.SystemSetting.key.in_(keys)).all()
    settings_map = {setting.key: setting for setting in records}
    # Ensure requested keys are present even if missing in DB
    for key in keys:
        settings_map.setdefault(key, None)
    return settings_map

def set_setting(db: Session, key: str, value: str):
    db_setting = get_setting(db, key)
    if db_setting:
        db_setting.value = value
    else:
        db_setting = models_db.SystemSetting(key=key, value=value)
        db.add(db_setting)
    db.commit()
    return db_setting

def set_settings(db: Session, values: Dict[str, str]):
    """Set multiple settings in one transaction."""
    if not values:
        return
    existing = db.query(models_db.SystemSetting).filter(models_db.SystemSetting.key.in_(values.keys())).all()
    existing_map = {setting.key: setting for setting in existing}

    for key, value in values.items():
        if key in existing_map:
            existing_map[key].value = value
        else:
            db.add(models_db.SystemSetting(key=key, value=value))

    db.commit()

def get_info_box_settings(db: Session) -> Dict[str, any]:
    enabled_setting = get_setting(db, INFO_BOX_ENABLED_KEY)
    content_setting = get_setting(db, INFO_BOX_CONTENT_KEY)
    title_setting = get_setting(db, INFO_BOX_TITLE_KEY)
    type_setting = get_setting(db, INFO_BOX_TYPE_KEY)

    return {
        "enabled": enabled_setting.value == 'true' if enabled_setting else False,
        "content": content_setting.value if content_setting else "",
        "title": title_setting.value if title_setting else "Server Information",
        "type": type_setting.value if type_setting else "info"
    }

def update_info_box_settings(db: Session, enabled: bool, content: str, title: str, box_type: str):
    set_setting(db, INFO_BOX_ENABLED_KEY, 'true' if enabled else 'false')
    set_setting(db, INFO_BOX_CONTENT_KEY, content)
    set_setting(db, INFO_BOX_TITLE_KEY, title)
    set_setting(db, INFO_BOX_TYPE_KEY, box_type)
