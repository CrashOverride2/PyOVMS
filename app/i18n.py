from fastapi import Request
from fastapi_babel import Babel, BabelConfigs, _
from pathlib import Path
from typing import Optional
import logging

from app.config import settings

logger = logging.getLogger(__name__)

__all__ = ['babel_configs', 'get_locale', 'babel', '_']

def get_locale(request: Request) -> Optional[str]:
    """
    Selects a locale for the request. This function is passed to the BabelMiddleware.
    Uses the browser's Accept-Language header to determine the preferred language.
    """
    accept_language = request.headers.get("Accept-Language")
    if accept_language:
        try:
            # Parse Accept-Language header (e.g., "en-US,en;q=0.9,de;q=0.8")
            languages = []
            for lang_entry in accept_language.split(","):
                lang_entry = lang_entry.strip()
                if ";" in lang_entry:
                    lang, quality = lang_entry.split(";", 1)
                    quality = float(quality.split("=")[1]) if "=" in quality else 1.0
                else:
                    lang, quality = lang_entry, 1.0

                # Normalize language code (e.g., "en-US" -> "en", "de-DE" -> "de")
                lang_code = lang.strip().split("-")[0].lower()
                languages.append((lang_code, quality))

            # Sort by quality score (higher first)
            languages.sort(key=lambda x: x[1], reverse=True)

            # Find first supported language
            for lang_code, _ in languages:
                if lang_code in settings.SUPPORTED_LOCALES:
                    logger.debug(f"get_locale: Using browser language '{lang_code}'")
                    return lang_code

        except Exception as e:
            logger.warning(f"get_locale: Error parsing Accept-Language header '{accept_language}': {e}")

    return None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRANSLATIONS_DIR = Path(__file__).resolve().parent / "translations"

babel_configs = BabelConfigs(
    ROOT_DIR=PROJECT_ROOT,
    BABEL_DEFAULT_LOCALE=settings.BABEL_DEFAULT_LOCALE,
    BABEL_TRANSLATION_DIRECTORY=str(TRANSLATIONS_DIR),
)

babel_configs.BABEL_COOKIE_NAME = settings.BABEL_LANG_COOKIE_NAME

babel = Babel(configs=babel_configs)