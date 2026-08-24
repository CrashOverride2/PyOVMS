import datetime
import secrets
import time
import logging
from typing import Dict, List, Literal, Optional
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

# Import at module level to avoid circular imports
_notification_send_func: Optional[callable] = None

def set_notification_function(func):
    """Set the notification function to avoid circular imports."""
    global _notification_send_func
    _notification_send_func = func

AuthType = Literal["login", "totp", "apikey", "v2tcp", "api_general"]


def _as_utc_timestamp(dt: datetime.datetime) -> float:
    """
    Epoch seconds for a datetime that may come back from the DB without a tzinfo.

    BlockedIP.unblock_at is DateTime(timezone=True) and is always written as aware
    UTC, but SQLite (and MySQL) return it naive. Calling .timestamp() on that naive
    value makes Python interpret UTC as *local* time, shifting every restored block
    by the server's UTC offset — east of UTC a 60-minute block is already expired by
    the time it is loaded, so brute-force blocks did not survive a restart at all.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()

class SecurityManager:
    """
    Manages rate limiting and temporary IP blocking for failed authentication attempts.
    This implementation uses the database for failure tracking to ensure safety 
    across multiple worker processes.
    """

    def __init__(self):
        self._lock = threading.Lock()
        
        # IP -> AuthType -> List of failure timestamps (kept for fast in-memory check if needed, 
        # but primary source is now the DB)
        self.failed_attempts: Dict[str, Dict[AuthType, List[float]]] = defaultdict(lambda: defaultdict(list))
        
        # IP -> Unblock timestamp (mirrored from DB)
        self.blocked_ips: Dict[str, float] = {}

        # Per-username distributed brute-force detection (in-memory second layer).
        #
        # The per-IP limits above are the primary defence, but they only see one
        # address. An attacker with a proxy pool spreads the attempts and never
        # reaches them, which is exactly the shape of a credential-stuffing or
        # TOTP-guessing run. Counting per *account* is what closes that.
        #
        # Tracked per auth type: reaching the TOTP step already required a valid
        # password, so those guesses come from someone who is demonstrably closer to
        # the account and deserve a tighter budget than password attempts. A 6-digit
        # code is only 10^6 wide — without this, rotating IPs is a viable way through.
        self._username_failures: Dict[AuthType, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._blocked_usernames: Dict[str, float] = {}
        self._username_failure_thresholds: Dict[AuthType, int] = {
            "login": 15,
            "totp": 10,
        }
        self._username_time_windows: Dict[AuthType, int] = {
            "login": 300,    # 5 minutes
            "totp": 900,     # 15 minutes — codes rotate every 30 s, so guessing is slow
        }
        self._username_block_duration_minutes: int = 15

        self.thresholds: Dict[AuthType, int] = {
            "login": 5,
            "totp": 5,
            "apikey": 10,
            "v2tcp": 10,
            "api_general": 100,
        }

        # Repeated-offender thresholds: crossing these extends the block, but only
        # to a bounded duration. Automated blocks are never permanent — the client
        # IP is not a trustworthy identity (NAT/CGNAT puts unrelated users behind
        # one address), so a permanent automated ban is a denial-of-service
        # primitive rather than a defence. Permanent bans are an admin decision,
        # available via block_ip_manually().
        self.extended_lockout_threshold: Dict[AuthType, int] = {
            "totp": 10,
        }
        self.extended_block_duration_minutes = 24 * 60

        self.time_windows: Dict[AuthType, int] = {
            "login": 60,
            "totp": 60,
            "apikey": 60,
            "v2tcp": 60,
            "api_general": 60,
        }
        
        self.block_duration_minutes = 60

    # ------------------------------------------------------------------
    # Database persistence helpers (errors are non-fatal)
    # ------------------------------------------------------------------

    def _db_record_failure(self, ip: str, auth_type: str, username: Optional[str] = None) -> int:
        """Records a failure in the DB and returns the count of failures in the current window."""
        try:
            from app.database import SessionLocal
            from app.models.db import SecurityFailure
            db = SessionLocal()
            try:
                # Add new failure
                db.add(SecurityFailure(ip_address=ip, auth_type=auth_type, username=username))
                db.commit()

                # Count recent failures within the sliding window
                window = self.time_windows.get(auth_type, 60)
                since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=window)
                count = db.query(SecurityFailure).filter(
                    SecurityFailure.ip_address == ip,
                    SecurityFailure.auth_type == auth_type,
                    SecurityFailure.created_at >= since
                ).count()

                # Cleanup old failures (maintenance)
                if secrets.randbelow(100) < 5:  # 5% chance to cleanup on record
                    cleanup_since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
                    db.query(SecurityFailure).filter(SecurityFailure.created_at < cleanup_since).delete()
                    db.commit()

                return count
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to record/count security failure in DB: {e}")
            return 0

    def _db_count_cumulative_failures(self, ip: str, auth_type: str, within_hours: int = 24) -> int:
        """Count all failures of a given auth_type for an IP within the given number of hours."""
        try:
            from app.database import SessionLocal
            from app.models.db import SecurityFailure
            db = SessionLocal()
            try:
                since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=within_hours)
                return db.query(SecurityFailure).filter(
                    SecurityFailure.ip_address == ip,
                    SecurityFailure.auth_type == auth_type,
                    SecurityFailure.created_at >= since
                ).count()
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to count cumulative failures for {ip}/{auth_type}: {e}")
            return 0

    def _db_count_username_failures(self, username: str, auth_type: str, within_seconds: int) -> Optional[int]:
        """
        Count recent failures for one account, across every IP and every worker.

        Returns None if the database could not answer, which the caller distinguishes
        from a zero count — falling back to the in-process counter is right, treating
        an error as "no failures" would not be.
        """
        try:
            from app.database import SessionLocal
            from app.models.db import SecurityFailure
            db = SessionLocal()
            try:
                since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=within_seconds)
                return db.query(SecurityFailure).filter(
                    SecurityFailure.username == username,
                    SecurityFailure.auth_type == auth_type,
                    SecurityFailure.created_at >= since
                ).count()
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to count username failures for '{username}'/{auth_type}: {e}")
            return None

    def _db_persist_block(self, ip: str, unblock_at: float, auth_type: str) -> None:
        """Write or update a blocked IP record in the database."""
        try:
            from app.database import SessionLocal
            from app.models.db import BlockedIP
            unblock_dt = datetime.datetime.fromtimestamp(unblock_at, tz=datetime.timezone.utc)
            db = SessionLocal()
            try:
                existing = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
                if existing:
                    existing.unblock_at = unblock_dt
                    existing.reason = auth_type
                else:
                    db.add(BlockedIP(ip=ip, unblock_at=unblock_dt, reason=auth_type))
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to persist blocked IP {ip} to database: {e}")

    def _db_remove_block(self, ip: str) -> None:
        """Delete an expired/lifted block from the database."""
        try:
            from app.database import SessionLocal
            from app.models.db import BlockedIP
            db = SessionLocal()
            try:
                db.query(BlockedIP).filter(BlockedIP.ip == ip).delete()
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to remove blocked IP {ip} from database: {e}")

    def load_from_db(self) -> None:
        """
        Load persisted blocked IPs from the database on startup.
        Call this once after the database is ready.
        """
        try:
            from app.database import SessionLocal
            from app.models.db import BlockedIP
            db = SessionLocal()
            try:
                now = datetime.datetime.now(datetime.timezone.utc)
                active = db.query(BlockedIP).filter(BlockedIP.unblock_at > now).all()
                expired = db.query(BlockedIP).filter(BlockedIP.unblock_at <= now).all()

                # Earlier versions wrote ~10-year blocks for repeat TOTP failures.
                # Clamp any automated block that outlives the current cap so those
                # legacy bans age out instead of persisting for a decade. Blocks
                # created by an admin (reason is free text, not an auth type) are
                # left untouched — a deliberate long ban stays a long ban.
                # Compare via timestamps: SQLite hands back naive datetimes, so
                # comparing model values against an aware datetime would raise.
                max_automated_ts = time.time() + (self.extended_block_duration_minutes * 60)
                max_automated = datetime.datetime.fromtimestamp(max_automated_ts, tz=datetime.timezone.utc)
                clamped = 0
                for row in active:
                    if row.reason in self.thresholds and _as_utc_timestamp(row.unblock_at) > max_automated_ts:
                        row.unblock_at = max_automated
                        clamped += 1

                with self._lock:
                    for row in active:
                        self.blocked_ips[row.ip] = _as_utc_timestamp(row.unblock_at)
                for row in expired:
                    db.delete(row)
                db.commit()
                logger.info(f"Loaded {len(active)} active blocked IP(s) from database.")
                if clamped:
                    logger.warning(
                        f"Shortened {clamped} legacy over-long automated IP block(s) to "
                        f"{self.extended_block_duration_minutes} minutes."
                    )
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to load blocked IPs from database: {e}")

    # ------------------------------------------------------------------

    def is_blocked(self, ip: str) -> bool:
        """Checks if an IP is currently blocked. Clears expired blocks."""
        expired = False
        with self._lock:
            unblock_time = self.blocked_ips.get(ip)
            if unblock_time is None:
                return False

            if time.time() >= unblock_time:
                del self.blocked_ips[ip]
                expired = True

        if expired:
            logger.info(f"IP address {ip} automatically unblocked.")
            self._db_remove_block(ip)
            return False

        return True

    def sweep_stale_username_entries(self) -> None:
        """Remove per-IP and per-username failure/block entries that are no longer active. Call hourly."""
        now = time.time()
        with self._lock:
            stale_failures = []
            for auth_type, bucket in self._username_failures.items():
                window = self._username_time_windows.get(auth_type, 300)
                for uname, timestamps in list(bucket.items()):
                    if not any(now - t <= window for t in timestamps):
                        del bucket[uname]
                        stale_failures.append(uname)

            expired_blocks = [
                uname for uname, unblock_at in self._blocked_usernames.items()
                if now >= unblock_at
            ]
            for uname in expired_blocks:
                del self._blocked_usernames[uname]

            # Same treatment for the per-IP mirror. Without this the dict grows
            # one entry per distinct source IP for the process lifetime, which a
            # spray across many addresses turns into unbounded memory growth.
            stale_ips = []
            for ip, per_type in self.failed_attempts.items():
                for auth_type in list(per_type.keys()):
                    window = self.time_windows.get(auth_type, 60)
                    per_type[auth_type] = [t for t in per_type[auth_type] if now - t <= window]
                    if not per_type[auth_type]:
                        del per_type[auth_type]
                if not per_type:
                    stale_ips.append(ip)
            for ip in stale_ips:
                del self.failed_attempts[ip]

        if stale_failures or expired_blocks or stale_ips:
            logger.debug(
                f"SecurityManager sweep: removed {len(stale_failures)} stale username failure "
                f"entries, {len(expired_blocks)} expired username blocks and "
                f"{len(stale_ips)} stale per-IP failure entries."
            )

    def unblock_ip(self, ip: str) -> bool:
        """
        Manually unblock an IP address (admin action).
        Returns True if the IP was found and removed, False if it wasn't blocked.
        """
        found = False
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                found = True
        self._db_remove_block(ip)
        if found:
            logger.info(f"IP address {ip} manually unblocked by admin.")
        return found

    def is_username_blocked(self, username: str) -> bool:
        """
        Check if a username is temporarily blocked due to distributed login failures.

        Answered from the `security_failures` table, not from process memory. The
        in-memory map this used to read is per worker, so the counter that exists
        specifically to catch an attacker rotating IP addresses was defeated by the
        attempts landing on different workers — and the record_failure() side already
        wrote every attempt to the database, so the data was there all along.

        An account counts as blocked while at least `threshold` failures of one type
        sit inside the block duration. That makes the block expire by the failures
        ageing out rather than by a stored deadline, which is what allows it to be
        stateless and therefore shared. A block is checked across all tracked auth
        types on purpose: an account being hammered at the TOTP step must not stay
        open at the password step.

        If the database cannot answer, the in-memory map is consulted instead, so a
        block already established in this process still holds.
        """
        uname = username.lower()
        block_window = self._username_block_duration_minutes * 60

        db_answered = False
        for auth_type, threshold in self._username_failure_thresholds.items():
            count = self._db_count_username_failures(uname, auth_type, block_window)
            if count is None:
                continue
            db_answered = True
            if count >= threshold:
                return True

        if db_answered:
            return False

        with self._lock:
            unblock_time = self._blocked_usernames.get(uname)
            if unblock_time is None:
                return False
            if time.time() >= unblock_time:
                del self._blocked_usernames[uname]
                logger.info(f"Username '{username}' automatically unblocked.")
                return False
            return True

    def block_ip_manually(self, ip: str, duration_minutes: int, reason: str) -> None:
        """
        Manually block an IP address for a given duration (admin action).
        """
        now = time.time()
        unblock_time = now + (duration_minutes * 60)
        with self._lock:
            self.blocked_ips[ip] = unblock_time
            # Clear any existing failure counters for this IP
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
        self._db_persist_block(ip, unblock_time, reason)
        self._log_security_event(
            "ip_blocked", ip,
            {"reason": reason, "block_duration_minutes": duration_minutes, "manual": True}
        )
        logger.info(f"IP address {ip} manually blocked for {duration_minutes} minutes (reason: {reason}).")

    def _log_security_event(self, event_type_str: str, ip: str, details: dict = None) -> None:
        """Log a security event to the database (non-fatal, opens its own session)."""
        try:
            from app.database import SessionLocal
            from app.security_events import security_event_logger, SecurityEventType
            db = SessionLocal()
            try:
                security_event_logger.log_event(
                    db=db,
                    event_type=SecurityEventType(event_type_str),
                    ip_address=ip,
                    details=details or {}
                )
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to log security event {event_type_str} for IP {ip}: {e}")

    def record_failure(self, ip: str, auth_type: AuthType, username: Optional[str] = None) -> bool:
        """
        Records a failed authentication attempt for an IP.
        Blocks the IP if the threshold is exceeded.
        For login failures, also tracks per-username across IPs (distributed brute-force).
        Returns True if the IP is now blocked, False otherwise.
        """
        if self.is_blocked(ip):
            logger.warning(f"Blocked IP {ip} attempted another failed '{auth_type}' login.")
            self._log_security_event("login_blocked", ip, {"auth_type": auth_type, "reason": "ip_already_blocked"})
            return True

        # Store the account name folded to lower case: is_username_blocked() counts
        # these rows, and it looks up the same folded form. Without this, "Admin" and
        # "admin" would be two separate budgets for one account.
        stored_username = username.lower() if username else None

        # 1. Record in DB and get global count (multi-worker safe)
        failure_count = self._db_record_failure(ip, auth_type, stored_username)
        
        block_event = None  # set to (unblock_time, failure_count) when threshold is crossed
        with self._lock:
            # Mirror the failure count in-memory for this instance's view.
            # Drop timestamps that have fallen out of the sliding window first —
            # otherwise the local count keeps growing forever and eventually
            # blocks a legitimate IP on failures that are hours or days apart.
            now = time.time()
            window = self.time_windows.get(auth_type, 60)
            self.failed_attempts[ip][auth_type] = [
                t for t in self.failed_attempts[ip][auth_type] if now - t <= window
            ]
            self.failed_attempts[ip][auth_type].append(now)

            # Use the higher of the two counts (local vs DB) to be safe
            local_count = len(self.failed_attempts[ip][auth_type])
            effective_count = max(failure_count, local_count)
            
            threshold = self.thresholds[auth_type]

            logger.warning(f"Failed '{auth_type}' attempt for IP {ip}. Count: {effective_count}/{threshold}")

            if effective_count >= threshold:
                unblock_time = now + (self.block_duration_minutes * 60)
                self.blocked_ips[ip] = unblock_time

                # Clean up memory for the now-blocked IP
                if ip in self.failed_attempts:
                    del self.failed_attempts[ip]

                logger.critical(
                    f"IP address {ip} has been blocked for {self.block_duration_minutes} minutes "
                    f"due to {effective_count} failed '{auth_type}' attempts."
                )
                block_event = (unblock_time, effective_count)

            # Per-username distributed brute-force detection.
            # This remains in-memory as a secondary defense layer.
            uname_threshold = self._username_failure_thresholds.get(auth_type)
            if uname_threshold is not None and username:
                uname = username.lower()
                uname_window = self._username_time_windows.get(auth_type, 300)
                bucket = self._username_failures[auth_type]
                bucket[uname] = [t for t in bucket[uname] if now - t <= uname_window]
                bucket[uname].append(now)
                uname_count = len(bucket[uname])
                if uname_count >= uname_threshold:
                    uname_unblock = now + (self._username_block_duration_minutes * 60)
                    # One shared block map across auth types on purpose: an account
                    # being hammered at the TOTP step must not stay open at the
                    # password step, and vice versa.
                    self._blocked_usernames[uname] = uname_unblock
                    del bucket[uname]
                    logger.warning(
                        f"Username '{username}' temporarily blocked for "
                        f"{self._username_block_duration_minutes} min after {uname_count} "
                        f"distributed '{auth_type}' failures."
                    )

        # DB and notification I/O outside the lock
        if block_event:
            unblock_time, final_count = block_event

            # Check cumulative repeat-offender threshold (e.g. TOTP: 10 total in 24h)
            ext_threshold = self.extended_lockout_threshold.get(auth_type)
            if ext_threshold is not None:
                cumulative = self._db_count_cumulative_failures(ip, auth_type, within_hours=24)
                if cumulative >= ext_threshold:
                    unblock_time = time.time() + (self.extended_block_duration_minutes * 60)
                    with self._lock:
                        self.blocked_ips[ip] = unblock_time
                    logger.critical(
                        f"IP {ip} blocked for {self.extended_block_duration_minutes} minutes: "
                        f"{cumulative} cumulative '{auth_type}' failures in 24h exceeds the "
                        f"extended-block threshold ({ext_threshold})."
                    )

            self._db_persist_block(ip, unblock_time, auth_type)
            self._log_security_event(
                "ip_blocked", ip,
                {"auth_type": auth_type, "failure_count": final_count, "block_duration_minutes": self.block_duration_minutes}
            )
            self._send_admin_notification(ip, auth_type, final_count)
            return True

        return False

    def _send_admin_notification(self, ip: str, auth_type: AuthType, failure_count: int):
        """Send email notification to admins when an IP is blocked.

        Subject and bodies are *templates*, not finished strings. That distinction is
        load-bearing: the renderer compiles whatever it is handed and caches the
        compiled result, so building the message here with the IP already substituted
        in meant a unique template per block event — a fresh Jinja parse of a full HTML
        document every time, evicting the templates that genuinely do repeat. Passing
        the IP as a variable makes all three sources constant and cacheable, and keeps
        request-derived data out of the template source.
        """
        if _notification_send_func is None:
            logger.debug("Notification function not set, skipping admin email")
            return

        try:
            # Imported here rather than at module scope: this module is deliberately
            # import-light so it can be pulled in from anywhere without cycles.
            from app.config import settings

            base_url = settings.SERVER_BASE_URL.rstrip('/')
            template_vars = {
                "ip_address": ip,
                "auth_type": auth_type,
                "failure_count": failure_count,
                "block_duration_minutes": self.block_duration_minutes,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
                    '%Y-%m-%d %H:%M:%S UTC'
                ),
                "server_base_url": settings.SERVER_BASE_URL,
                "security_events_url": f"{base_url}/admin/security-events",
            }

            # Still a thread: the send function opens a database session to resolve the
            # admin recipients and renders three templates before the message reaches
            # the outbound queue. None of that should happen on the thread that just
            # failed an authentication.
            threading.Thread(
                target=_notification_send_func,
                args=(
                    "\U0001f6a8 {{ _('OVMS Security Alert: IP Blocked') }} - {{ ip_address }}",
                    "email/admin_ip_blocked.txt",
                    "email/admin_ip_blocked.html",
                    template_vars,
                ),
                daemon=True,
            ).start()

        except Exception as e:
            logger.error(f"Failed to send admin notification for IP block: {e}", exc_info=True)


security_manager = SecurityManager()