import datetime
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

import requests
from sqlalchemy.orm import Session

from app.crud import system_setting

logger = logging.getLogger(__name__)

DEFAULT_REMOTE_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
DEFAULT_LOCAL_PATH = Path("data/disposable_email_domains.txt")
# Upper bound for the downloaded blocklist. The largest public lists are a few hundred
# kB; 16 MB leaves plenty of headroom while still bounding memory and disk.
_MAX_REMOTE_LIST_BYTES = 16 * 1024 * 1024

REMOTE_CACHE_PATH = Path("data/disposable_email_domains_remote.txt")
DEFAULT_REFRESH_HOURS = 24
_SETTINGS_KEYS = [
    "DISPOSABLE_EMAIL_FILTER_ENABLED",
    "DISPOSABLE_EMAIL_SOURCE",
    "DISPOSABLE_EMAIL_REMOTE_URL",
    "DISPOSABLE_EMAIL_LOCAL_PATH",
    "DISPOSABLE_EMAIL_REFRESH_HOURS",
    "DISPOSABLE_EMAIL_WHITELIST",
    "DISPOSABLE_EMAIL_LAST_FETCHED_AT",
]


class DisposableEmailError(Exception):
    """Base error for disposable email validation."""


class DisposableEmailBlocked(DisposableEmailError):
    def __init__(self, domain: str):
        super().__init__(f"Disposable email domains are not allowed: {domain}")
        self.domain = domain


class DisposableEmailListUnavailable(DisposableEmailError):
    def __init__(self, message: str):
        super().__init__(message)


@dataclass
class DisposableEmailConfig:
    enabled: bool = False
    source: str = "remote"  # "remote" or "local"
    refresh_hours: int = DEFAULT_REFRESH_HOURS
    remote_url: str = DEFAULT_REMOTE_URL
    local_path: Path = DEFAULT_LOCAL_PATH
    whitelist: Set[str] = field(default_factory=set)
    last_fetched_at: Optional[datetime.datetime] = None


class DisposableEmailService:
    def __init__(self):
        self._lock = threading.Lock()
        self._cached_domains: Set[str] = set()
        self._cached_whitelist: Set[str] = set()
        self._cached_config: Optional[DisposableEmailConfig] = None
        self._cached_signature: Optional[str] = None

    def _parse_bool(self, value: Optional[str], default: bool = False) -> bool:
        if value is None:
            return default
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _parse_int(self, value: Optional[str], default: int) -> int:
        try:
            parsed = int(value)
            return parsed if parsed >= 0 else default
        except (TypeError, ValueError):
            return default

    def _parse_datetime(self, value: Optional[str]) -> Optional[datetime.datetime]:
        if not value:
            return None
        try:
            parsed = datetime.datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        except ValueError:
            return None

    def _parse_whitelist(self, raw_value: Optional[str]) -> Set[str]:
        if not raw_value:
            return set()
        try:
            data = json.loads(raw_value)
            if isinstance(data, list):
                return {str(item).strip().lower() for item in data if str(item).strip()}
        except json.JSONDecodeError:
            pass

        entries = []
        for line in str(raw_value).splitlines():
            parts = [p.strip() for p in line.replace(",", " ").split(" ") if p.strip()]
            entries.extend(parts)
        return {entry.lower() for entry in entries if entry}

    def parse_whitelist_input(self, raw_value: Optional[str]) -> Set[str]:
        """Public helper to normalize whitelist input from forms."""
        return self._parse_whitelist(raw_value)

    def _load_config(self, db: Session) -> Tuple[DisposableEmailConfig, str]:
        settings_map = system_setting.get_settings_map(db, _SETTINGS_KEYS)

        def get_value(key: str, default: Optional[str] = None) -> Optional[str]:
            setting = settings_map.get(key)
            return setting.value if setting else default

        signature_parts = []
        for key in _SETTINGS_KEYS:
            setting = settings_map.get(key)
            updated = setting.updated_at.isoformat() if setting and setting.updated_at else "none"
            signature_parts.append(f"{key}:{updated}")
        signature = "|".join(signature_parts)

        config = DisposableEmailConfig(
            enabled=self._parse_bool(get_value("DISPOSABLE_EMAIL_FILTER_ENABLED"), False),
            source=(get_value("DISPOSABLE_EMAIL_SOURCE", "remote") or "remote").lower(),
            refresh_hours=self._parse_int(
                get_value("DISPOSABLE_EMAIL_REFRESH_HOURS"), DEFAULT_REFRESH_HOURS
            ),
            remote_url=get_value("DISPOSABLE_EMAIL_REMOTE_URL", DEFAULT_REMOTE_URL) or DEFAULT_REMOTE_URL,
            local_path=Path(
                get_value("DISPOSABLE_EMAIL_LOCAL_PATH", str(DEFAULT_LOCAL_PATH))
                or str(DEFAULT_LOCAL_PATH)
            ),
            whitelist=self._parse_whitelist(get_value("DISPOSABLE_EMAIL_WHITELIST")),
            last_fetched_at=self._parse_datetime(get_value("DISPOSABLE_EMAIL_LAST_FETCHED_AT")),
        )
        # Normalize allowed values
        if config.source not in {"remote", "local"}:
            config.source = "remote"
        logger.debug(
            "Disposable email config loaded: enabled=%s source=%s refresh_hours=%s remote_url=%s local_path=%s whitelist_count=%d last_fetched_at=%s signature=%s",
            config.enabled,
            config.source,
            config.refresh_hours,
            config.remote_url,
            config.local_path,
            len(config.whitelist),
            config.last_fetched_at,
            signature,
        )
        return config, signature

    def _parse_domains_from_text(self, text: str) -> Set[str]:
        domains = set()
        for line in text.splitlines():
            # Strip inline comments (everything after a #) and whitespace
            line_core = line.split("#", 1)[0]
            trimmed = line_core.strip().lower()
            if not trimmed:
                continue
            domains.add(trimmed)
        return domains

    def _load_from_file(self, path: Path) -> Set[str]:
        if not path.exists():
            logger.warning("Disposable email list file not found at %s", path)
            return set()
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            domains = self._parse_domains_from_text(content)
            logger.info("Loaded %d disposable email domains from %s", len(domains), path)
            return domains
        except Exception as exc:
            logger.error("Failed to read disposable email list from %s: %s", path, exc, exc_info=True)
            return set()

    def _write_cache(self, path: Path, domains: Set[str]) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(sorted(domains)), encoding="utf-8")
            logger.debug("Disposable email cache written to %s (count=%d)", path, len(domains))
        except Exception as exc:
            logger.warning("Unable to write disposable email cache to %s: %s", path, exc)

    def _should_refresh_remote(self, config: DisposableEmailConfig) -> bool:
        if not config.last_fetched_at:
            logger.debug("Disposable email remote refresh needed: no previous fetch timestamp.")
            return True
        if config.refresh_hours <= 0:
            return False
        next_refresh = config.last_fetched_at + datetime.timedelta(hours=config.refresh_hours)
        now = datetime.datetime.now(datetime.timezone.utc)
        should_refresh = now >= next_refresh
        if should_refresh:
            logger.debug(
                "Disposable email remote refresh needed: next_refresh=%s now=%s",
                next_refresh.isoformat(),
                now.isoformat(),
            )
        return should_refresh

    def _fetch_remote_domains(self, db: Session, config: DisposableEmailConfig) -> Set[str]:
        logger.info("Fetching disposable email list from remote source: %s", config.remote_url)

        from app.notifications.outbound import assert_safe_outbound_url
        try:
            assert_safe_outbound_url(config.remote_url, allowed_schemes=("https",))
        except ValueError as exc:
            raise DisposableEmailListUnavailable(f"Refusing to fetch disposable email list: {exc}") from exc

        try:
            response = requests.get(
                config.remote_url,
                timeout=20,
                allow_redirects=False,
                stream=True,
            )
            response.raise_for_status()
            # Without a cap the whole response is buffered into memory and then written
            # to disk; a hostile or broken source could exhaust either.
            chunks, total = [], 0
            for chunk in response.iter_content(chunk_size=64 * 1024, decode_unicode=False):
                total += len(chunk)
                if total > _MAX_REMOTE_LIST_BYTES:
                    raise DisposableEmailListUnavailable(
                        f"Disposable email list exceeds {_MAX_REMOTE_LIST_BYTES} bytes; aborting download."
                    )
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")
        except requests.RequestException as exc:
            raise DisposableEmailListUnavailable(f"Unable to download disposable email list: {exc}") from exc
        finally:
            try:
                response.close()
            except Exception:
                pass

        domains = self._parse_domains_from_text(body)
        if not domains:
            raise DisposableEmailListUnavailable("Downloaded disposable email list is empty.")
        logger.info("Fetched %d disposable email domains from remote.", len(domains))

        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        system_setting.set_setting(db, "DISPOSABLE_EMAIL_LAST_FETCHED_AT", now_str)
        self._write_cache(REMOTE_CACHE_PATH, domains)
        return domains

    def _load_domains_for_config(
        self, db: Session, config: DisposableEmailConfig, refresh_due: Optional[bool] = None
    ) -> Set[str]:
        # Remote source: refresh on schedule or when cache is empty
        if config.source == "remote":
            refresh_due = self._should_refresh_remote(config) if refresh_due is None else refresh_due

            # First try to hydrate from previously downloaded cache on disk
            if not self._cached_domains:
                cached_file_domains = self._load_from_file(REMOTE_CACHE_PATH)
                if cached_file_domains:
                    self._cached_domains = cached_file_domains
                    logger.info(
                        "Loaded disposable email domains from cached file %s (count=%d).",
                        REMOTE_CACHE_PATH,
                        len(cached_file_domains),
                    )

            if not self._cached_domains:
                logger.info("Disposable email cache empty; fetching remote list.")
            elif refresh_due:
                logger.info(
                    "Disposable email remote refresh triggered (last_fetched_at=%s, refresh_hours=%s).",
                    config.last_fetched_at,
                    config.refresh_hours,
                )

            if not self._cached_domains or refresh_due:
                try:
                    self._cached_domains = self._fetch_remote_domains(db, config)
                    config.last_fetched_at = datetime.datetime.now(datetime.timezone.utc)
                except DisposableEmailListUnavailable as exc:
                    logger.warning("%s", exc)
                    if self._cached_domains:
                        logger.info(
                            "Using previously cached disposable email domains after refresh failure (count=%d).",
                            len(self._cached_domains),
                        )
                        return self._cached_domains
                    fallback = self._load_from_file(REMOTE_CACHE_PATH)
                    if fallback:
                        self._cached_domains = fallback
                        logger.info(
                            "Using on-disk remote cache for disposable email domains (count=%d).", len(fallback)
                        )
                        return fallback
                    raise
            return self._cached_domains

        # Local source
        logger.info("Loading disposable email domains from local file: %s", config.local_path)
        domains = self._load_from_file(config.local_path)
        if not domains:
            raise DisposableEmailListUnavailable(
                f"Local disposable email list is empty or missing at {config.local_path}"
            )
        self._cached_domains = domains
        return domains

    def _reload_if_needed(
        self, db: Session, config: DisposableEmailConfig, signature: str
    ) -> Tuple[DisposableEmailConfig, Set[str]]:
        with self._lock:
            refresh_due = config.source == "remote" and self._should_refresh_remote(config)
            reasons = []
            needs_reload = (
                self._cached_config is None
                or self._cached_signature != signature
                or (self._cached_config and self._cached_config.source != config.source)
                or (config.source == "local" and self._cached_config and self._cached_config.local_path != config.local_path)
                or refresh_due
            )
            if self._cached_config is None:
                reasons.append("no cached config")
            if self._cached_signature != signature:
                reasons.append("settings changed")
            if self._cached_config and self._cached_config.source != config.source:
                reasons.append("source changed")
            if config.source == "local" and self._cached_config and self._cached_config.local_path != config.local_path:
                reasons.append("local path changed")
            if refresh_due:
                reasons.append("refresh interval reached")
            if not self._cached_domains:
                reasons.append("empty cache")

            if needs_reload:
                logger.info("Reloading disposable email domains (%s).", ", ".join(reasons))
                domains = self._load_domains_for_config(db, config, refresh_due=refresh_due)
            else:
                domains = self._cached_domains
                logger.debug("Using cached disposable email domains (count=%d).", len(domains))

            # Always refresh cached config/whitelist to reflect new toggles without restart
            self._cached_config = config
            self._cached_signature = signature
            self._cached_whitelist = config.whitelist
            return config, domains

    def _is_domain_blocked(self, domain: str, domains: Set[str], whitelist: Set[str]) -> bool:
        if domain in whitelist:
            return False
        if domain in domains:
            return True

        # Block subdomains when parent is in blocklist and respect wildcards
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = "*." + ".".join(parts[i + 1 :])
            if candidate in domains and domain not in whitelist:
                return True
            parent = ".".join(parts[i + 1 :])
            if parent in domains and domain not in whitelist:
                return True
        return False

    def check_email(self, db: Session, email: str) -> None:
        """
        Validate an email address against the configured disposable domain settings.
        Raises DisposableEmailBlocked when blocked, DisposableEmailListUnavailable if the list cannot be loaded.
        """
        config, signature = self._load_config(db)
        if not config.enabled:
            return

        domain = email.split("@")[-1].lower().strip() if "@" in email else ""
        if not domain:
            raise DisposableEmailBlocked("unknown")

        config, domains = self._reload_if_needed(db, config, signature)
        whitelist = config.whitelist if config else set()

        if self._is_domain_blocked(domain, domains, whitelist):
            logger.info("Disposable email blocked: %s (domains cached=%d, whitelist=%d)", domain, len(domains), len(whitelist))
            raise DisposableEmailBlocked(domain)
        else:
            logger.debug("Disposable email allowed: %s (filter enabled=%s, cached domains=%d)", domain, config.enabled, len(domains))

    def update_settings(
        self,
        db: Session,
        *,
        enabled: bool,
        source: str,
        remote_url: str,
        local_path: str,
        refresh_hours: int,
        whitelist: Set[str],
    ) -> None:
        source_value = source.lower() if source in {"remote", "local"} else "remote"
        refresh_value = refresh_hours if refresh_hours >= 0 else DEFAULT_REFRESH_HOURS
        values: Dict[str, str] = {
            "DISPOSABLE_EMAIL_FILTER_ENABLED": "true" if enabled else "false",
            "DISPOSABLE_EMAIL_SOURCE": source_value,
            "DISPOSABLE_EMAIL_REMOTE_URL": remote_url or DEFAULT_REMOTE_URL,
            "DISPOSABLE_EMAIL_LOCAL_PATH": local_path or str(DEFAULT_LOCAL_PATH),
            "DISPOSABLE_EMAIL_REFRESH_HOURS": str(refresh_value),
            "DISPOSABLE_EMAIL_WHITELIST": json.dumps(sorted(whitelist)),
        }
        system_setting.set_settings(db, values)
        logger.info(
            "Disposable email settings updated (enabled=%s source=%s refresh_hours=%s remote_url=%s local_path=%s whitelist_count=%d).",
            enabled,
            source_value,
            refresh_value,
            remote_url,
            local_path,
            len(whitelist),
        )
        with self._lock:
            self._cached_signature = None  # force reload on next check

    def refresh_remote_now(self, db: Session) -> int:
        """Force a remote fetch and return the number of domains loaded."""
        config, _ = self._load_config(db)
        config.source = "remote"
        domains = self._fetch_remote_domains(db, config)
        with self._lock:
            self._cached_domains = domains
            self._cached_config = config
            self._cached_signature = None
        logger.info("Manual refresh of disposable email domains completed (count=%d).", len(domains))
        return len(domains)

    def warm_cache(self, db: Session) -> None:
        """
        Attempt to load the disposable email domains at startup so the cache
        is primed before any user interaction.
        """
        logger.info("Warming disposable email domain cache...")
        try:
            config, signature = self._load_config(db)
            _, domains = self._reload_if_needed(db, config, signature)
            logger.info(
                "Disposable email cache warmed (count=%d, source=%s, last_fetched_at=%s).",
                len(domains),
                config.source,
                config.last_fetched_at,
            )
        except DisposableEmailListUnavailable as exc:
            logger.warning("Disposable email cache warm-up failed: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error during disposable email cache warm-up: %s", exc, exc_info=True)

    def get_state(self, db: Session) -> Dict[str, object]:
        """Return the current configuration and cache info for display purposes."""
        config, signature = self._load_config(db)
        domains: Set[str] = set()
        error: Optional[str] = None

        # Ensure domains are loaded so the admin dashboard doesn't show 0 on startup.
        try:
            config, domains = self._reload_if_needed(db, config, signature)
        except DisposableEmailListUnavailable as exc:
            error = str(exc)
            with self._lock:
                domains = set(self._cached_domains)

        with self._lock:
            cached_count = len(domains)
            whitelist = sorted(config.whitelist)
            last_loaded_source = (
                "remote" if config.source == "remote" else f"local ({config.local_path})"
            )
            logger.debug(
                "Disposable email state requested: cached_count=%d whitelist_count=%d last_source=%s error=%s",
                cached_count,
                len(whitelist),
                last_loaded_source,
                error,
            )

        return {
            "config": config,
            "signature": signature,
            "cached_count": cached_count,
            "whitelist": whitelist,
            "last_loaded_source": last_loaded_source,
            "error": error,
        }


disposable_email_service = DisposableEmailService()
