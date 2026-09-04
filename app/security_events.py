"""
Security Events Logging and Monitoring

This module provides comprehensive security event logging for the admin dashboard.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.models import db as models_db

logger = logging.getLogger(__name__)


class SecurityEventType(str, Enum):
    """Types of security events to track."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGIN_BLOCKED = "login_blocked"
    LOGOUT = "logout"
    TOTP_SUCCESS = "totp_success"
    TOTP_FAILED = "totp_failed"
    TOTP_ENABLED = "totp_enabled"
    TOTP_DISABLED = "totp_disabled"
    WEBAUTHN_REGISTERED = "webauthn_registered"
    WEBAUTHN_SUCCESS = "webauthn_success"
    WEBAUTHN_FAILED = "webauthn_failed"
    WEBAUTHN_REMOVED = "webauthn_removed"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_EXPIRED = "api_key_expired"
    CSRF_VIOLATION = "csrf_violation"
    RATE_LIMIT_HIT = "rate_limit_hit"
    IP_BLOCKED = "ip_blocked"
    IP_UNBLOCKED = "ip_unblocked"
    SESSION_HIJACK_ATTEMPT = "session_hijack_attempt"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PERMISSION_DENIED = "permission_denied"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_DISABLED = "user_disabled"
    USER_ENABLED = "user_enabled"
    ADMIN_GRANTED = "admin_granted"
    ADMIN_REVOKED = "admin_revoked"
    ADMIN_ACTION = "admin_action"
    DISPOSABLE_EMAIL_BLOCKED = "disposable_email_blocked"
    MQTT_SYNC_FAILED = "mqtt_sync_failed"


class SecurityEventSeverity(str, Enum):
    """Severity levels for security events."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SecurityEventLogger:
    """Centralized security event logging."""

    # Map event types to severities
    EVENT_SEVERITIES = {
        SecurityEventType.LOGIN_SUCCESS: SecurityEventSeverity.INFO,
        SecurityEventType.LOGIN_FAILED: SecurityEventSeverity.WARNING,
        SecurityEventType.LOGIN_BLOCKED: SecurityEventSeverity.ERROR,
        SecurityEventType.TOTP_FAILED: SecurityEventSeverity.WARNING,
        SecurityEventType.WEBAUTHN_FAILED: SecurityEventSeverity.WARNING,
        SecurityEventType.PASSWORD_CHANGED: SecurityEventSeverity.INFO,
        SecurityEventType.API_KEY_CREATED: SecurityEventSeverity.INFO,
        SecurityEventType.CSRF_VIOLATION: SecurityEventSeverity.ERROR,
        SecurityEventType.RATE_LIMIT_HIT: SecurityEventSeverity.WARNING,
        SecurityEventType.IP_BLOCKED: SecurityEventSeverity.CRITICAL,
        SecurityEventType.SESSION_HIJACK_ATTEMPT: SecurityEventSeverity.CRITICAL,
        SecurityEventType.SUSPICIOUS_ACTIVITY: SecurityEventSeverity.ERROR,
        SecurityEventType.PERMISSION_DENIED: SecurityEventSeverity.WARNING,
        SecurityEventType.DISPOSABLE_EMAIL_BLOCKED: SecurityEventSeverity.WARNING,
        SecurityEventType.MQTT_SYNC_FAILED: SecurityEventSeverity.ERROR,
        # Both directions are worth a WARNING, not an INFO. Granting admin is the
        # escalation an attacker with a stolen admin key performs to survive the
        # key being revoked; revoking it from someone else is how they lock the
        # real operators out. Neither is routine on a running server.
        SecurityEventType.ADMIN_GRANTED: SecurityEventSeverity.WARNING,
        SecurityEventType.ADMIN_REVOKED: SecurityEventSeverity.WARNING,
    }

    @staticmethod
    def log_event(
        db: Session,
        event_type: SecurityEventType,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: Optional[SecurityEventSeverity] = None
    ) -> models_db.SecurityEvent:
        """
        Log a security event.

        Args:
            db: Database session
            event_type: Type of security event
            user_id: User ID if applicable
            username: Username if known
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional event details
            severity: Override auto-determined severity

        Returns:
            Created SecurityEvent object
        """
        # Auto-determine severity if not provided
        if severity is None:
            severity = SecurityEventLogger.EVENT_SEVERITIES.get(
                event_type,
                SecurityEventSeverity.INFO
            )

        event = models_db.SecurityEvent(
            event_type=event_type.value,
            severity=severity.value,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
            created_at=datetime.now(timezone.utc)
        )

        db.add(event)
        db.commit()

        # Also log to application logger
        log_level = {
            SecurityEventSeverity.INFO: logging.INFO,
            SecurityEventSeverity.WARNING: logging.WARNING,
            SecurityEventSeverity.ERROR: logging.ERROR,
            SecurityEventSeverity.CRITICAL: logging.CRITICAL,
        }.get(severity, logging.INFO)

        logger.log(
            log_level,
            f"Security Event: {event_type.value} | User: {username or 'N/A'} | "
            f"IP: {ip_address or 'N/A'} | Details: {details}"
        )

        return event

    @staticmethod
    def get_recent_events(
        db: Session,
        limit: int = 100,
        user_id: Optional[int] = None,
        event_type: Optional[SecurityEventType] = None,
        severity: Optional[SecurityEventSeverity] = None,
        hours: int = 24
    ) -> List[models_db.SecurityEvent]:
        """
        Get recent security events with optional filtering.

        Args:
            db: Database session
            limit: Maximum number of events to return
            user_id: Filter by user ID
            event_type: Filter by event type
            severity: Filter by severity
            hours: Look back this many hours

        Returns:
            List of SecurityEvent objects
        """
        query = db.query(models_db.SecurityEvent)

        # Time filter
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = query.filter(models_db.SecurityEvent.created_at >= since)

        # Optional filters
        if user_id:
            query = query.filter(models_db.SecurityEvent.user_id == user_id)
        if event_type:
            query = query.filter(models_db.SecurityEvent.event_type == event_type.value)
        if severity:
            query = query.filter(models_db.SecurityEvent.severity == severity.value)

        return query.order_by(desc(models_db.SecurityEvent.created_at)).limit(limit).all()

    @staticmethod
    def get_event_statistics(
        db: Session,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get security event statistics for dashboard.

        Args:
            db: Database session
            hours: Look back this many hours

        Returns:
            Dictionary with event statistics
        """
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Total events by severity
        severity_counts = db.query(
            models_db.SecurityEvent.severity,
            func.count(models_db.SecurityEvent.id)
        ).filter(
            models_db.SecurityEvent.created_at >= since
        ).group_by(
            models_db.SecurityEvent.severity
        ).all()

        # Total events by type
        type_counts = db.query(
            models_db.SecurityEvent.event_type,
            func.count(models_db.SecurityEvent.id)
        ).filter(
            models_db.SecurityEvent.created_at >= since
        ).group_by(
            models_db.SecurityEvent.event_type
        ).all()

        # Failed login attempts by IP
        failed_logins_by_ip = db.query(
            models_db.SecurityEvent.ip_address,
            func.count(models_db.SecurityEvent.id).label('count')
        ).filter(
            models_db.SecurityEvent.created_at >= since,
            models_db.SecurityEvent.event_type.in_([
                SecurityEventType.LOGIN_FAILED.value,
                SecurityEventType.TOTP_FAILED.value
            ])
        ).group_by(
            models_db.SecurityEvent.ip_address
        ).order_by(
            desc('count')
        ).limit(10).all()

        # Blocked IPs
        blocked_ips = db.query(
            models_db.SecurityEvent.ip_address,
            func.max(models_db.SecurityEvent.created_at).label('blocked_at')
        ).filter(
            models_db.SecurityEvent.created_at >= since,
            models_db.SecurityEvent.event_type == SecurityEventType.IP_BLOCKED.value
        ).group_by(
            models_db.SecurityEvent.ip_address
        ).all()

        return {
            "time_range_hours": hours,
            "severity_counts": dict(severity_counts),
            "type_counts": dict(type_counts),
            "failed_logins_by_ip": [
                {"ip": ip, "count": count}
                for ip, count in failed_logins_by_ip
            ],
            "blocked_ips": [
                {"ip": ip, "blocked_at": blocked_at}
                for ip, blocked_at in blocked_ips
            ],
            "total_events": sum(count for _, count in severity_counts)
        }

    @staticmethod
    def cleanup_old_events(db: Session, days: int = 90) -> int:
        """
        Clean up security events older than specified days.

        Args:
            db: Database session
            days: Delete events older than this many days

        Returns:
            Number of events deleted
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        deleted = db.query(models_db.SecurityEvent).filter(
            models_db.SecurityEvent.created_at < cutoff
        ).delete()

        db.commit()

        logger.info(f"Cleaned up {deleted} security events older than {days} days")
        return deleted


# Convenience function for easy import
security_event_logger = SecurityEventLogger()


def log_admin_role_change(
    db: Session,
    *,
    target_id: int,
    target_username: str,
    granted: bool,
    actor: "models_db.User",
    ip_address: Optional[str],
    via: str,
) -> None:
    """
    Record a change to a user's admin flag.

    Nothing recorded this. USER_CREATED said only that an account was created, and the
    edit routes logged an event solely when is_active moved — so the single most
    consequential change an account can undergo, being handed administrative rights,
    left the audit trail indistinguishable from a name correction. That is the change
    someone holding a stolen admin credential makes first, because a second admin
    account outlives the revocation of the key or password that created it.

    Shared by the API and the UI so both spell the event the same way; `via` says which
    route it came from. Never raises — an unwritable audit row must not turn a
    completed administrative change into a 500.
    """
    try:
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.ADMIN_GRANTED if granted else SecurityEventType.ADMIN_REVOKED,
            user_id=target_id,
            username=target_username,
            ip_address=ip_address,
            details={"changed_by": actor.username, "changed_by_user_id": actor.id, "via": via},
        )
    except Exception:
        logger.exception("Failed to record admin role change for user '%s'", target_username)
