"""
Security Events API endpoints.
"""
import ipaddress
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.db import User, SecurityEvent, BlockedIP
from app.dependencies import require_admin_user_from_cookie_or_api
from app.security_manager import security_manager
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, field_validator
import datetime

router = APIRouter()


class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    severity: str
    user_id: Optional[int]
    username: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Optional[Dict[str, Any]]
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class SecurityStatisticsResponse(BaseModel):
    total_events: int
    severity_counts: Dict[str, int]
    event_type_counts: Dict[str, int]
    failed_logins_by_ip: List[Dict[str, Any]]
    blocked_ips: List[Dict[str, Any]]


class BlockedIPResponse(BaseModel):
    ip: str
    reason: Optional[str]
    created_at: datetime.datetime
    unblock_at: datetime.datetime

    class Config:
        from_attributes = True


class BlockIPRequest(BaseModel):
    ip: str
    duration_minutes: int = 60
    reason: str = "manual_admin_block"

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address")
        return v

    @field_validator("duration_minutes")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v < 1 or v > 525600:  # max 1 year
            raise ValueError("duration_minutes must be between 1 and 525600")
        return v


@router.get("/blocked-ips", response_model=List[BlockedIPResponse])
def list_blocked_ips(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api),
):
    """List all currently active blocked IP addresses."""
    now = datetime.datetime.now(datetime.timezone.utc)
    rows = (
        db.query(BlockedIP)
        .filter(BlockedIP.unblock_at > now)
        .order_by(BlockedIP.unblock_at.asc())
        .all()
    )
    return rows


@router.post("/blocked-ips", response_model=BlockedIPResponse, status_code=status.HTTP_201_CREATED)
def block_ip(
    request: Request,
    body: BlockIPRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api),
):
    """Manually block an IP address for a given duration."""
    security_manager.block_ip_manually(body.ip, body.duration_minutes, body.reason)
    now = datetime.datetime.now(datetime.timezone.utc)
    row = db.query(BlockedIP).filter(BlockedIP.ip == body.ip).first()
    if not row:
        # DB write may have failed; return a synthetic response
        return BlockedIPResponse(
            ip=body.ip,
            reason=body.reason,
            created_at=now,
            unblock_at=now + datetime.timedelta(minutes=body.duration_minutes),
        )
    db.refresh(row)
    return row


@router.delete("/blocked-ips/{ip}", status_code=status.HTTP_204_NO_CONTENT)
def unblock_ip(
    ip: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api),
):
    """Unblock a previously blocked IP address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid IP address")
    security_manager.unblock_ip(ip)


@router.get("/statistics", response_model=SecurityStatisticsResponse)
def get_security_statistics(
    request: Request,
    hours: int = Query(24, ge=1, le=720),  # 1 hour to 30 days
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api)
):
    """
    Get security event statistics for the last N hours.
    Requires admin privileges (cookie or API key authentication).
    """

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)

    events = db.query(SecurityEvent).filter(
        SecurityEvent.created_at >= cutoff
    ).all()

    # Total count
    total_events = len(events)

    # Severity counts
    severity_counts = {}
    for event in events:
        severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1

    # Event type counts
    event_type_counts = {}
    for event in events:
        event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1

    # Failed logins by IP
    failed_login_ips = {}
    failed_login_types = ["login_failed", "totp_failed", "webauthn_failed"]

    for event in events:
        if event.event_type in failed_login_types:
            if event.ip_address:
                failed_login_ips[event.ip_address] = failed_login_ips.get(event.ip_address, 0) + 1

    failed_logins_by_ip = [
        {"ip": ip, "count": count}
        for ip, count in sorted(failed_login_ips.items(), key=lambda x: x[1], reverse=True)
    ]

    # Blocked IPs
    blocked_events = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "ip_blocked",
        SecurityEvent.created_at >= cutoff
    ).order_by(SecurityEvent.created_at.desc()).all()

    blocked_ips = [
        {"ip": event.ip_address, "blocked_at": event.created_at.isoformat()}
        for event in blocked_events
    ]

    return SecurityStatisticsResponse(
        total_events=total_events,
        severity_counts=severity_counts,
        event_type_counts=event_type_counts,
        failed_logins_by_ip=failed_logins_by_ip,
        blocked_ips=blocked_ips
    )


@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    request: Request,
    hours: int = Query(24, ge=1, le=720),
    severity: Optional[str] = Query(None, pattern="^(info|warning|error|critical)$"),
    event_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api)
):
    """
    Get security events with optional filtering.
    Requires admin privileges (cookie or API key authentication).
    """

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)

    query = db.query(SecurityEvent).filter(
        SecurityEvent.created_at >= cutoff
    )

    # Apply filters
    if severity:
        query = query.filter(SecurityEvent.severity == severity)

    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)

    # Order by most recent first
    query = query.order_by(SecurityEvent.created_at.desc())

    # Apply pagination
    events = query.offset(offset).limit(limit).all()

    return events


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
def get_security_event(
    event_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_user_from_cookie_or_api)
):
    """
    Get a specific security event by ID.
    Requires admin privileges (cookie or API key authentication).
    """

    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found"
        )

    return event
