from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Callable, Optional, Dict, Tuple
import datetime
from jinja2 import pass_context
from jinja2.utils import htmlsafe_json_dumps
import logging
from zoneinfo import ZoneInfo
from babel.support import Translations

from app.config import settings
from app.models import db as models_db
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from babel.dates import format_datetime
from app.csrf_protection import get_csrf_token

logger = logging.getLogger(__name__)

APP_DIR = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = APP_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.add_extension('jinja2.ext.i18n')

templates.env.globals['source_code_url'] = settings.SOURCE_CODE_URL

TRANSLATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "translations"

templates.env.install_null_translations()

translations_cache = {}
for locale in settings.SUPPORTED_LOCALES:
    locale_path = TRANSLATIONS_DIR / locale / "LC_MESSAGES"
    if locale_path.exists():
        try:
            trans = Translations.load(str(TRANSLATIONS_DIR), [locale])
            translations_cache[locale] = trans
            logger.info(f"Loaded translations for locale: {locale}")
        except Exception as e:
            logger.error(f"Failed to load translations for {locale}: {e}")

@pass_context
def custom_datetime_formatter(context: Dict, value: datetime.datetime, format_str: Optional[str] = None) -> str:
    """
    Custom filter to format datetimes using the correct user-defined timezone and locale.
    """
    if not isinstance(value, datetime.datetime):
        return str(value) if value is not None else ""

    user_tz_str = 'UTC'
    if context.get('current_user') and getattr(context['current_user'], 'timezone', None):
        user_tz_str = context['current_user'].timezone
    
    request = context.get('request')
    locale_str = settings.BABEL_DEFAULT_LOCALE
    if request and hasattr(request.state, 'babel') and hasattr(request.state.babel, 'locale'):
        locale_str = str(request.state.babel.locale)

    is_german = locale_str.startswith('de')
    format_presets = {
        'full': 'dd.MM.yyyy HH:mm:ss' if is_german else 'yyyy-MM-dd HH:mm:ss',
        'medium_date': 'dd.MM.yyyy' if is_german else 'yyyy-MM-dd',
    }

    if format_str in format_presets:
        final_format = format_presets[format_str]
    elif format_str:
        final_format = format_str
    else:
        final_format = format_presets['full']

    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        
        user_tz = ZoneInfo(user_tz_str)
        localized_dt = value.astimezone(user_tz)
        
        return format_datetime(localized_dt, format=final_format, locale=locale_str)
    except Exception as e:
        logger.error(f"Error formatting datetime '{value}' with timezone '{user_tz_str}': {e}", exc_info=True)
        return str(value)

def latest_timestamp_filter(timestamps: Tuple[Optional[datetime.datetime], ...]) -> Optional[datetime.datetime]:
    """
    Takes a tuple of datetime objects and returns the most recent one.
    Handles timezone-aware and naive datetime comparisons gracefully by making naive ones aware.
    """
    aware_timestamps = []
    for ts in timestamps:
        if ts:
            if ts.tzinfo is None:
                aware_timestamps.append(ts.replace(tzinfo=datetime.timezone.utc))
            else:
                aware_timestamps.append(ts)
    
    return max(aware_timestamps) if aware_timestamps else None

templates.env.filters['latest_timestamp'] = latest_timestamp_filter

@pass_context
def tojson_filter(context, value):
    """
    Serialise a value to JSON for embedding in a template.

    Must go through htmlsafe_json_dumps, which escapes <, >, & and ' as \\u00XX.
    Plain json.dumps() does not, and wrapping its output in Markup additionally
    suppresses the surrounding autoescaping — a vehicle-supplied metric value
    containing "</script>" would then break straight out of the <script> block
    it is rendered into. Every `| tojson` in the template tree relies on this
    function for that escaping, so it must not be "simplified" back to
    json.dumps. Covered by tests/test_template_escaping.py.
    """
    return htmlsafe_json_dumps(jsonable_encoder(value))

def humanize_key(key: str) -> str:
    if not isinstance(key, str):
        return key
    return key.replace('_', ' ').capitalize()

def get_request_locale(request: Request) -> str:
    """The locale BabelMiddleware picked for this request, or the configured default."""
    if hasattr(request.state, 'babel') and hasattr(request.state.babel, 'locale'):
        return str(request.state.babel.locale)
    return settings.BABEL_DEFAULT_LOCALE


def get_translator(request: Request) -> Callable[[str], str]:
    """
    gettext for this request's locale, without building a template context.

    For routes that answer with a redirect rather than a page. Those carry their
    message in the query string (`?success_message=…`), and the message was written
    into it as an English literal — so the flash line above an otherwise translated
    page stayed English no matter what the browser asked for. They cannot use the `_`
    from get_common_template_vars() without paying for a CSRF token, three filesystem
    checks and the whole settings fan-out to format one sentence.

    Messages that interpolate a value must use *named* placeholders and the `%`
    operator — `_("Vehicle '%(id)s' added.") % {"id": vid}` — never an f-string. An
    f-string is formatted before gettext ever sees it, so the lookup is a different
    string on every call and always misses; named placeholders also let a translator
    reorder them, which positional %s does not.
    """
    locale = get_request_locale(request)
    translations = translations_cache.get(locale)
    return translations.gettext if translations else (lambda text: text)


def get_common_template_vars(request: Request, current_user: Optional[models_db.User]) -> dict:
    # Install the appropriate translation for this request
    # Uses locale determined by BabelMiddleware from browser's Accept-Language header
    user_locale = get_request_locale(request)

    if user_locale in translations_cache:
        templates.env.install_gettext_translations(translations_cache[user_locale])
    else:
        templates.env.install_null_translations()

    fcm_path_str = settings.FCM_CREDENTIALS_PATH
    is_fcm_configured = False
    if isinstance(fcm_path_str, str) and fcm_path_str:
        if Path(fcm_path_str).exists():
            is_fcm_configured = True

    apns_configured = all([
        settings.APNS_AUTH_KEY_PATH and Path(settings.APNS_AUTH_KEY_PATH).exists(),
        settings.APNS_KEY_ID,
        settings.APNS_TEAM_ID,
        settings.APNS_TOPIC
    ])

    gettext = get_translator(request)

    is_mqtt_configured = bool(settings.MQTT_PASSWD_FILE and settings.MQTT_ACL_FILE)

    # Generate CSRF token for this request
    csrf_token = get_csrf_token(request)

    return {
        "request": request,
        "_": gettext,
        "current_year": datetime.datetime.now(datetime.timezone.utc).year,
        "global_ntfy_server": settings.NTFY_SERVER,
        "global_ntfy_default_topic": settings.NTFY_DEFAULT_TOPIC,
        "global_email_configured": bool(settings.EMAIL_HOST and settings.EMAIL_SENDER),
        "global_fcm_configured": is_fcm_configured,
        "global_apns_configured": apns_configured,
        "is_mqtt_configured": is_mqtt_configured,
        "current_user": current_user,
        "user_timezone": current_user.timezone if current_user and current_user.timezone else "UTC",
        "user_prefers_imperial": (getattr(current_user, 'unit_preference', 'metric') == 'imperial') if current_user else False,
        "user_locale": user_locale,
        "is_admin": current_user.is_admin if current_user else False,
        "settings": settings,
        "PROTOMAPS_URL": settings.PROTOMAPS_URL,
        "csrf_token": csrf_token,
    }
