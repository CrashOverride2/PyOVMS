from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Index, LargeBinary, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import false as sa_false
from app.database import Base
import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    timezone = Column(String(100), nullable=False, default="UTC", server_default="UTC")
    unit_preference = Column(String(10), nullable=False, default="metric", server_default="metric")
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    account_deletion_reminder_sent_at = Column(DateTime(timezone=True), nullable=True)

    token_version = Column(Integer, nullable=False, default=0, server_default='0')

    is_totp_enabled = Column(Boolean, default=False, nullable=False)
    encrypted_totp_secret = Column(LargeBinary, nullable=True)
    totp_key_version = Column(Integer, nullable=True)

    webauthn_enabled = Column(Boolean, default=False, nullable=False)

    email_verification_token = Column(String(128), unique=True, index=True, nullable=True)
    email_verification_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    password_reset_token = Column(String(128), unique=True, index=True, nullable=True)
    password_reset_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    vehicles = relationship("Vehicle", back_populates="owner", cascade="all, delete-orphan")
    auto_provision_profiles = relationship("AutoProvisionProfile", back_populates="owner", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    webauthn_credentials = relationship("WebAuthnCredential", back_populates="user", cascade="all, delete-orphan") 

    def __repr__(self):
        return f"<User(username='{self.username}', admin={self.is_admin})>"

class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(Integer, primary_key=True, index=True)
    vehicle_id = Column(String(32), unique=True, index=True, nullable=False) 
    vehicle_name = Column(String(100), index=True) 
    encrypted_server_password = Column(LargeBinary, nullable=False)
    encrypted_module_password = Column(LargeBinary, nullable=True)

    protocol = Column(String(10), nullable=False, default='both')
    notification_preference = Column(String(10), nullable=True, default='v3')

    owner_id = Column(Integer, ForeignKey("users.id", name="fk_vehicle_owner_id"), nullable=False, index=True)
    owner = relationship("User", back_populates="vehicles")

    latest_status_msg = Column(Text) 
    latest_location_msg = Column(Text) 
    latest_diag_msg = Column(Text) 
    latest_firmware_msg = Column(Text) 
    latest_tpms_w_msg = Column(Text) 
    latest_tpms_y_msg = Column(Text) 
    latest_export_power_msg = Column(Text, nullable=True)

    paranoid_token = Column(LargeBinary, nullable=True)

    enable_ntfy_notifications = Column(Boolean, default=False)
    enable_email_notifications = Column(Boolean, default=False)
    enable_fcm_notifications = Column(Boolean, default=False)
    enable_apns_notifications = Column(Boolean, default=False, nullable=False)
    enable_trip_tracking = Column(Boolean, default=False, nullable=False)
    enable_charge_logging = Column(Boolean, default=False, nullable=False)
    enable_unified_push_notifications = Column(Boolean, default=False, nullable=False)
    unified_push_endpoint = Column(String(500), nullable=True)
    badge_count = Column(Integer, default=0, nullable=False)

    ntfy_topic = Column(String(100))
    ntfy_server_url = Column(String(255))
    ntfy_auth_method = Column(String(50))
    ntfy_auth_token = Column(LargeBinary, nullable=True)
    ntfy_auth_user = Column(String(100))
    ntfy_auth_password = Column(LargeBinary, nullable=True)
    ntfy_auth_query_param_name = Column(String(50))

    notification_email = Column(String(255)) 

    fcm_token = Column(String(255)) 
    apns_token = Column(String(255)) 

    last_seen_tcp = Column(DateTime(timezone=True), index=True, nullable=True)
    last_seen_v3 = Column(DateTime(timezone=True), index=True, nullable=True)
    last_message_at = Column(DateTime(timezone=True), index=True, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
    unused_reminder_sent_at = Column(DateTime(timezone=True), nullable=True)

    historical_data = relationship(
        "HistoricalData",
        foreign_keys="[HistoricalData.vehicle_id_fk]",
        back_populates="vehicle",
        cascade="all, delete-orphan" 
    )
    auto_provision_profile_assoc = relationship(
        "AutoProvisionProfile",
        uselist=False, 
        foreign_keys="[AutoProvisionProfile.vehicle_id_fk]",
        back_populates="target_vehicle_obj",
        cascade="all, delete-orphan" 
    )
    charge_logs = relationship("ChargeLog", back_populates="vehicle", cascade="all, delete-orphan")
    push_subscriptions = relationship("PushSubscription", back_populates="vehicle", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Vehicle(vehicle_id='{self.vehicle_id}', name='{self.vehicle_name}')>"

class PushSubscription(Base):
    """Per-device push notification subscription. Supports FCM, APNs, UnifiedPush (app-registered)
    and manually added ntfy topics and e-mail recipients (push_type 'ntfy'/'email')."""
    __tablename__ = "push_subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    vehicle_id_fk = Column(Integer, ForeignKey("vehicles.id", name="fk_pushsub_vehicle_id", ondelete="CASCADE"), nullable=False, index=True)
    # Device fingerprint for app-registered types; topic/email used as key for manual types.
    device_id = Column(String(255), nullable=False)
    # 'fcm', 'apns', 'up', 'ntfy', or 'email'
    push_type = Column(String(10), nullable=False)
    # Token/URL for push types; topic for ntfy; address for email
    endpoint = Column(String(500), nullable=False)
    # ntfy-specific optional fields (null for all other types)
    ntfy_server_url = Column(String(255), nullable=True)
    ntfy_auth_method = Column(String(50), nullable=True)
    ntfy_auth_token = Column(LargeBinary, nullable=True)
    ntfy_auth_user = Column(String(100), nullable=True)
    ntfy_auth_password = Column(LargeBinary, nullable=True)
    ntfy_auth_query_param_name = Column(String(50), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))

    vehicle = relationship("Vehicle", back_populates="push_subscriptions")

    __table_args__ = (
        UniqueConstraint("vehicle_id_fk", "device_id", "push_type", name="uq_pushsub_vehicle_device_type"),
        Index("ix_pushsub_vehicle_type", "vehicle_id_fk", "push_type"),
    )

    def __repr__(self):
        return f"<PushSubscription(vehicle_fk={self.vehicle_id_fk}, device='{self.device_id[:8]}', type='{self.push_type}')>"


class HistoricalData(Base):
    __tablename__ = "historical_data"
    id = Column(Integer, primary_key=True, index=True)
    vehicle_id_fk = Column(Integer, ForeignKey("vehicles.id", name="fk_historicaldata_vehicle_id"), nullable=False)
    
    vehicle_module_id_str = Column(String(32), index=True, nullable=False)

    timestamp = Column(DateTime(timezone=True), nullable=False, index=True) 
    
    record_type = Column(String(50), nullable=False) 
    record_number = Column(Integer, nullable=True) 
    
    data_payload = Column(Text, nullable=False) 
    expires_at = Column(DateTime(timezone=True), index=True, nullable=True) 

    vehicle = relationship("Vehicle", foreign_keys=[vehicle_id_fk], back_populates="historical_data")

    __table_args__ = (
        Index('ix_historical_data_vehicle_fk_timestamp', "vehicle_id_fk", "timestamp"),
        Index('ix_historical_data_vehicle_str_id_timestamp', "vehicle_module_id_str", "timestamp"),
        Index('ix_historical_data_vehicle_str_rectype_time', "vehicle_module_id_str", "record_type", "timestamp"),
        Index('ix_historical_data_vehicle_rectype_recnum_time',
              "vehicle_id_fk", "record_type", "record_number", "timestamp", unique=True,
              sqlite_where=(Column("record_type").isnot(None) & Column("record_number").isnot(None))
             ),
    )
    def __repr__(self):
        return f"<HistoricalData(vehicle_fk='{self.vehicle_id_fk}', type='{self.record_type}', time='{self.timestamp}')>"


class AutoProvisionProfile(Base):
    __tablename__ = "auto_provision_profiles"
    id = Column(Integer, primary_key=True, index=True)
    ap_key = Column(String(100), unique=True, index=True, nullable=False) 

    owner_id = Column(Integer, ForeignKey("users.id", name="fk_autoprovision_owner_id"), nullable=False, index=True)
    owner = relationship("User", back_populates="auto_provision_profiles")

    target_vehicle_id_str = Column(String(32), unique=True, nullable=False) 
    target_server_password = Column(LargeBinary, nullable=False)
    target_vehicle_name = Column(String(100))
    target_module_password = Column(LargeBinary, nullable=True)

    encrypted_module_params_b64 = Column(Text) 

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc))

    vehicle_id_fk = Column(Integer, ForeignKey("vehicles.id", name="fk_autoprovision_target_vehicle_id"), unique=True, nullable=True)
    target_vehicle_obj = relationship("Vehicle", foreign_keys=[vehicle_id_fk], back_populates="auto_provision_profile_assoc")

    def __repr__(self):
        return f"<AutoProvisionProfile(ap_key='{self.ap_key}', target_vehicle_id='{self.target_vehicle_id_str}')>"

class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_prefix = Column(String(8), nullable=False, index=True) 
    hashed_key = Column(String(128), nullable=False, unique=True, index=True) 
    user_id = Column(Integer, ForeignKey("users.id", name="fk_apikey_user_id"), nullable=False)
    name = Column(String(100), nullable=False) 
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Set only by the device-provisioning endpoint. It drives the sliding expiry, so
    # it has to be an explicit fact about the row rather than something inferred from
    # the name: a key an existing user had already called "device-tesla" and given a
    # deliberate 30-day expiry would otherwise have started renewing itself to 180
    # days on every request.
    is_device_key = Column(Boolean, default=False, nullable=False, server_default=sa_false())

    user = relationship("User", back_populates="api_keys")

    def __repr__(self):
        return f"<ApiKey(name='{self.name}', user_id={self.user_id}, prefix='{self.key_prefix}')>"

class SystemSetting(Base):
    __tablename__ = "system_settings"
    key = Column(String(50), primary_key=True, index=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))

    def __repr__(self):
        return f"<SystemSetting(key='{self.key}')>"


class WebAuthnCredential(Base):
    """WebAuthn/FIDO2 security key credentials."""
    __tablename__ = "webauthn_credentials"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", name="fk_webauthn_user_id"), nullable=False)
    credential_id = Column(String(255), nullable=False, unique=True, index=True)
    public_key = Column(Text, nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    credential_name = Column(String(100), nullable=True)
    credential_type = Column(String(50), nullable=True)  # platform/cross-platform
    usage_mode = Column(String(20), nullable=False, default='passwordless')  # 'passwordless' or '2fa'
    # Whether the authenticator stored this credential on itself (a "resident key").
    #
    # Deliberately three-valued: True/False come from the credProps.rk extension the
    # browser reports at registration, NULL means "registered before we asked and
    # therefore unknown". The passwordless login needs the distinction — a discoverable
    # credential is found by the authenticator on its own, so the server can stay silent
    # about which credentials exist, while an unknown one still has to be named in
    # allowCredentials or the user cannot sign in at all. See ui/webauthn.py.
    #
    # Not every authenticator returns credProps, so False and NULL are both treated as
    # "must be named" — the conservative direction, since guessing wrong here locks a
    # passwordless-only account out of its own server.
    is_discoverable = Column(Boolean, nullable=True, default=None)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    user = relationship("User", back_populates="webauthn_credentials")

    def __repr__(self):
        return f"<WebAuthnCredential(id={self.id}, user_id={self.user_id}, name='{self.credential_name}', mode='{self.usage_mode}')>"


class BlockedIP(Base):
    """Persistent storage for rate-limited / blocked IP addresses."""
    __tablename__ = "blocked_ips"

    ip = Column(String(45), primary_key=True)  # IPv6 max length
    unblock_at = Column(DateTime(timezone=True), nullable=False, index=True)
    reason = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.datetime.now(datetime.timezone.utc))

    def __repr__(self):
        return f"<BlockedIP(ip='{self.ip}', unblock_at='{self.unblock_at}')>"


class SecurityEvent(Base):
    """Security event logging for audit trail and monitoring."""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", name="fk_security_event_user_id"), nullable=True)
    username = Column(String(50), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)  # IPv6 max length
    user_agent = Column(String(255), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index('ix_security_events_created_at_severity', "created_at", "severity"),
        Index('ix_security_events_user_id_created_at', "user_id", "created_at"),
    )

    def __repr__(self):
        return f"<SecurityEvent(type='{self.event_type}', severity='{self.severity}', user='{self.username}')>"


class SecurityFailure(Base):
    """Tracks individual failed authentication attempts for rate limiting across workers."""
    __tablename__ = "security_failures"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    auth_type = Column(String(20), nullable=False, index=True)
    username = Column(String(50), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True,
                        default=lambda: datetime.datetime.now(datetime.timezone.utc))

    def __repr__(self):
        return f"<SecurityFailure(ip='{self.ip_address}', type='{self.auth_type}', user='{self.username}')>"


class UsedTotpCode(Base):
    """
    TOTP codes already spent, so one cannot be replayed inside its validity window.

    A code stays valid for up to 90 s (the 30 s step plus one step either side for
    clock drift), which is long enough for someone who captured it — over the
    shoulder, from a phishing page, out of a proxy log — to use it a second time.

    This was an in-process dictionary, which made the protection true only for a
    single-worker deployment: with two workers, the replay simply had to land on the
    other one. The unique constraint below does the same job across processes and
    does it atomically — the insert either succeeds or raises, with no window between
    checking and recording for a concurrent request to slip through.

    `code_key` is a hash, never the code itself: this table would otherwise be a list
    of recently valid second factors.
    """
    __tablename__ = "used_totp_codes"

    id = Column(Integer, primary_key=True, index=True)
    code_key = Column(String(64), nullable=False, unique=True, index=True)
    used_at = Column(DateTime(timezone=True), nullable=False, index=True,
                     default=lambda: datetime.datetime.now(datetime.timezone.utc))

    def __repr__(self):
        return f"<UsedTotpCode(used_at='{self.used_at}')>"