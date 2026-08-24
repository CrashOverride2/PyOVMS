import logging
import logging.handlers
import os
import re
import stat
from pathlib import Path
from app.config import settings


# Secrets that travel in a URL and would otherwise be written verbatim by
# uvicorn.access: single-use WebSocket tickets (?ticket=), password-reset tokens
# (/reset-password/<token>) and e-mail verification tokens (/verify/<token>).
# A reset token is valid for an hour, so anyone who can read LOG_FILE — or an
# admin watching the live log stream — could take over the account before the
# legitimate user clicks the link.
_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"([?&](?:ticket|token|api_key|access_token)=)[^&\s\"']+", re.I), r"\1<redacted>"),
    (re.compile(r"(/(?:reset-password|verify)/)[^/\s?\"']+", re.I), r"\1<redacted>"),
)


class RedactingFilter(logging.Filter):
    """Strip URL-borne secrets from log records before they reach any handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in _REDACTIONS:
                record.msg = pattern.sub(replacement, record.msg)
        if record.args:
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            scrubbed = []
            for arg in args:
                if isinstance(arg, str):
                    for pattern, replacement in _REDACTIONS:
                        arg = pattern.sub(replacement, arg)
                scrubbed.append(arg)
            record.args = tuple(scrubbed) if isinstance(record.args, tuple) else scrubbed[0]
        return True


class OwnerOnlyRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    RotatingFileHandler that keeps the log file at 0600.

    Application logs carry request paths, usernames, IPs and security-event
    detail, so they should not be world-readable. The default handler creates
    files with the process umask (usually 0644) and re-creates them on every
    rollover, so the mode is enforced after each open rather than once at setup.
    """

    def _open(self):
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Never let a permissions problem take down logging entirely.
            pass
        return stream


class SafeFormatter(logging.Formatter):
    """Formatter that strips newline/carriage-return characters to prevent log injection."""

    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, str):
            record.msg = record.msg.replace('\n', '\\n').replace('\r', '\\r')
        return super().format(record)


class SafeUvicornFormatter(SafeFormatter):
    """Safe formatter that preserves uvicorn's colour level-prefix rendering."""

    def __init__(self, *args, use_colors: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, 'levelprefix'):
            separator = " " * (8 - len(record.levelname))
            record.levelprefix = f"{record.levelname}:{separator}"
        return super().format(record)

    def formatMessage(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        # Delegate actual formatting to the parent; sanitisation happens in format()
        return super().formatMessage(record)

log_level = getattr(settings, 'LOG_LEVEL', 'INFO').upper()

handlers_config = {
    "default": {
        "formatter": "default",
        "class": "logging.StreamHandler",
        "stream": "ext://sys.stderr",
        "filters": ["redact"],
    },
}

if settings.LOG_FILE:
    log_file_path = Path(settings.LOG_FILE)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    handlers_config["file"] = {
        "formatter": "file",
        "class": "app.logging_config.OwnerOnlyRotatingFileHandler",
        "filename": str(log_file_path),
        "maxBytes": 5 * 1024 * 1024,
        "backupCount": 5,
        "encoding": "utf-8",
        "filters": ["redact"],
    }

active_handlers = list(handlers_config.keys())

LOGGING_CONFIG: dict[str, any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "redact": {"()": "app.logging_config.RedactingFilter"},
    },
    "formatters": {
        "default": {
            "()": "app.logging_config.SafeUvicornFormatter",
            "fmt": "%(levelprefix)s %(asctime)s - %(name)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "use_colors": True,
        },
        "file": {
            "()": "app.logging_config.SafeFormatter",
            "fmt": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": handlers_config,
    "loggers": {
        "": {
            "handlers": active_handlers,
            "level": "WARNING",
        },
        "app": {
            "handlers": active_handlers,
            "level": log_level,
            "propagate": False,
        },
        "alembic": {
             "handlers": active_handlers,
             "level": "INFO",
             "propagate": False,
        },
        "uvicorn.error": {
            "handlers": active_handlers,
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": active_handlers,
            "level": "INFO",
            "propagate": False,
        },
    },
}