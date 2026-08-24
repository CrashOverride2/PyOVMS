from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List, Dict, Any
import datetime
import ipaddress
import re
from urllib.parse import urlparse

from app.utils.email_validation import validate_optional_email_address


def _validate_push_endpoint_url(v: Optional[str]) -> Optional[str]:
    """Reject non-https schemes and IP-literal private/loopback/reserved addresses."""
    if not v:
        return v
    parsed = urlparse(v)
    if parsed.scheme != 'https':
        raise ValueError('UnifiedPush endpoint must use https://')
    host = (parsed.hostname or '').lower()
    if not host or host == 'localhost':
        raise ValueError('UnifiedPush endpoint must not target localhost')
    try:
        addr = ipaddress.ip_address(host)
        if not addr.is_global:
            raise ValueError('UnifiedPush endpoint must use a globally routable address')
    except ValueError as exc:
        if 'UnifiedPush' in str(exc):
            raise
        # Not an IP literal — hostname is fine (DNS resolution not done at validate time)
    return v

def _validate_ntfy_server_url(v: Optional[str]) -> Optional[str]:
    """Reject non-http/https schemes and IP-literal private/loopback/reserved addresses (SSRF prevention)."""
    if not v:
        return v
    parsed = urlparse(v)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('NTFY server URL must use http:// or https://')
    host = (parsed.hostname or '').lower()
    if not host or host == 'localhost':
        raise ValueError('NTFY server URL must not target localhost')
    try:
        addr = ipaddress.ip_address(host)
        if not addr.is_global:
            raise ValueError('NTFY server URL must use a globally routable address')
    except ValueError as exc:
        if 'NTFY server' in str(exc):
            raise
        # Not an IP literal — hostname is fine (DNS resolution not done at validate time)
    return v

PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]{12,128}$"
PASSWORD_ERROR_MESSAGE = (
    "Password must be between 12 and 128 characters long and include at least one uppercase letter, "
    "one lowercase letter, one digit, and one special character."
)

def validate_password_strength(password: str) -> str:
    """Reusable validator for password strength."""
    if not re.match(PASSWORD_REGEX, password):
        raise ValueError(PASSWORD_ERROR_MESSAGE)
    return password

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username contains only alphanumeric characters, underscore, and hyphen (no spaces or special characters)."""
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', v):
            raise ValueError('Username must only contain letters, numbers, underscores, and hyphens (no spaces or special characters)')
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=12, max_length=128)
    is_admin: bool = False
    timezone: str = 'UTC'

    _validate_password = field_validator('password')(validate_password_strength)


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=100)
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=12, max_length=128)
    timezone: Optional[str] = Field(None, max_length=100)
    unit_preference: Optional[str] = Field(None, max_length=10)

    @field_validator('username')
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        """Validate username contains only alphanumeric characters, underscore, and hyphen (no spaces or special characters)."""
        if v is not None and not re.fullmatch(r'[a-zA-Z0-9_-]+', v):
            raise ValueError('Username must only contain letters, numbers, underscores, and hyphens (no spaces or special characters)')
        return v

    @field_validator('password', mode='before')
    @classmethod
    def validate_optional_password(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            return validate_password_strength(value)
        return value

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)

    _validate_new_password = field_validator('new_password')(validate_password_strength)


class UserInfo(UserBase):
    id: int
    is_admin: bool
    created_at: datetime.datetime
    updated_at: datetime.datetime
    is_totp_enabled: bool = False
    timezone: str = 'UTC'

    class Config:
        from_attributes = True

class UserInDB(UserInfo):
    hashed_password: str

# --- Token Models ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- Vehicle Models ---
class VehicleInfo(BaseModel):
    id: Optional[int] = None
    vehicle_id: str
    vehicle_name: Optional[str] = None
    owner_username: Optional[str] = None
    protocol: str = 'both'
    notification_preference: Optional[str] = 'v3'
    enable_trip_tracking: bool = False
    enable_charge_logging: bool = False
    enable_unified_push_notifications: bool = False
    unified_push_endpoint: Optional[str] = None
    badge_count: int = 0

    connection_type: Optional[str] = None
    address: Optional[str] = None
    authenticated: bool = False

    latest_status_parsed: Optional[Dict[str, Any]] = None
    latest_location_parsed: Optional[Dict[str, Any]] = None
    latest_tpms_parsed: Optional[Dict[str, Any]] = None
    latest_diag_parsed: Optional[Dict[str, Any]] = None

    enable_ntfy_notifications: bool = False
    enable_email_notifications: bool = False
    enable_fcm_notifications: bool = False
    enable_apns_notifications: bool = False

    ntfy_topic: Optional[str] = None
    ntfy_server_url: Optional[str] = None
    notification_email: Optional[str] = None
    fcm_token: Optional[str] = None
    apns_token: Optional[str] = None

    last_seen_tcp: Optional[datetime.datetime] = None
    last_seen_v3: Optional[datetime.datetime] = None
    last_message_at: Optional[datetime.datetime] = None
    unused_reminder_sent_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

# The vehicle server password is not a display name: it is the HMAC key for the V2
# handshake *and* the module's Mosquitto password. min_length=1 allowed a one-character
# secret, which is brute-forceable offline in seconds from a single captured handshake.
# 12 is the same floor the auto-provisioning key already used.
MIN_VEHICLE_PASSWORD_LENGTH = 12


class VehicleCreate(BaseModel):
    vehicle_id: str = Field(..., min_length=1, max_length=32)
    vehicle_name: Optional[str] = Field(None, max_length=100)
    server_password: str = Field(..., min_length=MIN_VEHICLE_PASSWORD_LENGTH, max_length=64)
    module_password: Optional[str] = Field(None, max_length=32)
    protocol: str = Field('both', description="Protocol to use: 'v2', 'v3', or 'both'")
    notification_preference: Optional[str] = Field('v3', description="For 'both' protocol, which one should send notifications: 'v2' or 'v3'")
    enable_trip_tracking: bool = False
    enable_charge_logging: bool = False
    enable_unified_push_notifications: bool = False
    badge_count: int = 0

    enable_ntfy_notifications: bool = False
    enable_email_notifications: bool = False
    enable_fcm_notifications: bool = False
    enable_apns_notifications: bool = False

    ntfy_topic: Optional[str] = Field(None, max_length=100)
    ntfy_server_url: Optional[str] = Field(None, max_length=255)
    ntfy_auth_method: Optional[str] = Field(None, max_length=50)
    ntfy_auth_token: Optional[str] = Field(None, max_length=255)
    ntfy_auth_user: Optional[str] = Field(None, max_length=100)
    ntfy_auth_password: Optional[str] = Field(None, max_length=100)
    ntfy_auth_query_param_name: Optional[str] = Field(None, max_length=50)

    notification_email: Optional[str] = Field(None, max_length=255)
    fcm_token: Optional[str] = Field(None, max_length=255, description="Firebase Cloud Messaging (FCM) token for Android push notifications.")
    apns_token: Optional[str] = Field(None, max_length=255, description="Apple Push Notification service (APNs) token for iOS push notifications.")
    unified_push_endpoint: Optional[str] = Field(None, max_length=500, description="UnifiedPush endpoint URL for open-standard push notifications.")
    paranoid_token: Optional[str] = Field(None, max_length=64)
    owner_id: Optional[int] = None

    @field_validator('vehicle_id', mode='before')
    @classmethod
    def vehicle_id_alphanumeric_upper(cls, v):
        if not isinstance(v, str):
            raise ValueError('Vehicle ID must be a string')
        v_upper = v.upper()
        if not re.fullmatch(r"[A-Z0-9-]+", v_upper):
            raise ValueError('Vehicle ID must only contain letters, numbers, and hyphens')
        return v_upper

    @field_validator('unified_push_endpoint')
    @classmethod
    def validate_unified_push_endpoint(cls, v):
        return _validate_push_endpoint_url(v)

    @field_validator('ntfy_server_url')
    @classmethod
    def validate_ntfy_server_url(cls, v):
        return _validate_ntfy_server_url(v)

    @field_validator('notification_email')
    @classmethod
    def validate_notification_email(cls, v):
        return validate_optional_email_address(v)

class VehicleUpdate(BaseModel):
    vehicle_id: Optional[str] = Field(None, min_length=1, max_length=32)
    vehicle_name: Optional[str] = Field(None, max_length=100)
    server_password: Optional[str] = Field(None, min_length=MIN_VEHICLE_PASSWORD_LENGTH, max_length=64)
    module_password: Optional[str] = Field(None, max_length=32)
    protocol: Optional[str] = None
    notification_preference: Optional[str] = None
    enable_trip_tracking: Optional[bool] = None
    enable_charge_logging: Optional[bool] = None
    enable_unified_push_notifications: Optional[bool] = None
    unified_push_endpoint: Optional[str] = Field(None, max_length=500, validate_default=False, description="UnifiedPush endpoint URL for open-standard push notifications.")
    badge_count: Optional[int] = None

    enable_ntfy_notifications: Optional[bool] = None
    enable_email_notifications: Optional[bool] = None
    enable_fcm_notifications: Optional[bool] = None
    enable_apns_notifications: Optional[bool] = None

    ntfy_topic: Optional[str] = Field(None, max_length=100, validate_default=False)
    ntfy_server_url: Optional[str] = Field(None, max_length=255, validate_default=False)
    ntfy_auth_method: Optional[str] = Field(None, max_length=50, validate_default=False)
    ntfy_auth_token: Optional[str] = Field(None, max_length=255, validate_default=False)
    ntfy_auth_user: Optional[str] = Field(None, max_length=100, validate_default=False)
    ntfy_auth_password: Optional[str] = Field(None, max_length=100, validate_default=False)
    ntfy_auth_query_param_name: Optional[str] = Field(None, max_length=50, validate_default=False)

    notification_email: Optional[str] = Field(None, max_length=255, validate_default=False)
    fcm_token: Optional[str] = Field(None, max_length=255, validate_default=False, description="Firebase Cloud Messaging (FCM) token for Android push notifications.")
    apns_token: Optional[str] = Field(None, max_length=255, validate_default=False, description="Apple Push Notification service (APNs) token for iOS push notifications.")
    paranoid_token: Optional[str] = Field(None, max_length=64, validate_default=False)

    @field_validator('vehicle_id', mode='before')
    @classmethod
    def vehicle_id_upper_if_present(cls, v):
        if v is not None:
            if not isinstance(v, str):
                raise ValueError('Vehicle ID must be a string')
            v_upper = v.upper()
            if not re.fullmatch(r"[A-Z0-9-]+", v_upper):
                raise ValueError('Vehicle ID must only contain letters, numbers, and hyphens')
            return v_upper
        return v

    @field_validator('unified_push_endpoint')
    @classmethod
    def validate_unified_push_endpoint(cls, v):
        return _validate_push_endpoint_url(v)

    @field_validator('ntfy_server_url')
    @classmethod
    def validate_ntfy_server_url(cls, v):
        return _validate_ntfy_server_url(v)

    @field_validator('notification_email')
    @classmethod
    def validate_notification_email(cls, v):
        return validate_optional_email_address(v)

class VehicleSecureInfo(VehicleInfo):
    """
    Enhanced vehicle info for detail views. 
    NOTE: Sensitive passwords (server_password, module_password) are NEVER 
    returned in API responses for security, even if they exist in the DB.
    """

# --- Command Models ---
class CommandRequest(BaseModel):
    command_code_with_args: str = Field(..., description="Full command string, e.g., '7,wakeup' or '11'")

class CommandResponse(BaseModel):
    vehicle_id: str
    response_data: Optional[str] = None
    success: bool
    error_message: Optional[str] = None

# --- Status Models ---
class StatusResponse(BaseModel):
    vehicle_id: str
    is_connected: bool
    data: Dict[str, Any] 
    last_seen_tcp: Optional[datetime.datetime] = None
    last_message_at: Optional[datetime.datetime] = None

# --- Notification Models ---
class NtfySubscriptionRequest(BaseModel): 
    vehicle_id: str
    ntfy_topic: str

class ManualNotificationRequest(BaseModel):
    message: str
    title: Optional[str] = None
    priority: Optional[int] = 3
    tags: Optional[List[str]] = None

# --- Auto Provisioning Models ---
class AutoProvisionProfileBase(BaseModel):
    target_vehicle_id: str = Field(..., max_length=32)
    target_vehicle_name: Optional[str] = Field(None, max_length=100)
    is_active: bool = True
    owner_id: Optional[int] = None

    @field_validator('target_vehicle_id', mode='before')
    @classmethod
    def target_vehicle_id_upper(cls, v):
        return v.upper()

class AutoProvisionProfileCreate(AutoProvisionProfileBase):
    ap_key: str = Field(..., min_length=12, max_length=100)
    target_server_password: str = Field(..., min_length=MIN_VEHICLE_PASSWORD_LENGTH, max_length=32)
    target_module_password: Optional[str] = Field(None, max_length=32)
    encrypted_module_params_b64: Optional[str] = None

    @field_validator('ap_key', mode='before')
    @classmethod
    def ap_key_strip_and_validate(cls, v):
        if not isinstance(v, str):
            return v
        key = v.strip()
        if len(key) < 12:
            raise ValueError("Auto-provisioning key must be at least 12 characters long.")
        return key

class AutoProvisionProfileInfo(AutoProvisionProfileBase):
    """
    Auto-provisioning profile info for list/detail views.
    NOTE: Sensitive keys and passwords are NEVER returned in API responses.
    """
    id: int
    created_at: datetime.datetime
    owner_username: Optional[str] = None

    class Config:
        from_attributes = True

# --- API Key Models ---
class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="A descriptive name for the API key.")
    expires_in_days: Optional[int] = Field(None, ge=1, description="Number of days until the key expires. Leave null for no expiry.")

    @field_validator('name')
    @classmethod
    def reject_reserved_name(cls, v: str) -> str:
        """Reserved prefixes mark keys the server issues for itself and skip the quota."""
        from app.crud.apikey import is_reserved_key_name

        if is_reserved_key_name(v):
            raise ValueError('This API key name is reserved for internal use. Please choose another name.')
        return v

class ApiKeyInfo(BaseModel):
    id: int
    name: str
    key_prefix: str
    created_at: datetime.datetime
    expires_at: Optional[datetime.datetime]
    last_used_at: Optional[datetime.datetime]
    is_active: bool

    class Config:
        from_attributes = True

class ApiKeyCreateResponse(ApiKeyInfo):
    full_key: str = Field(..., description="The full API key. This is shown only once.")

# --- 2FA Models ---
class TOTPSetupInfo(BaseModel):
    otpauth_uri: str 

class TOTPEnableRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, description="The 6-digit code from the authenticator app.")

class WsTicketResponse(BaseModel):
    app_ws_ticket: str
    mqtt_username: Optional[str] = None
    mqtt_password: Optional[str] = None

# --- Metrics Models ---
class AvailableMetricsResponse(BaseModel):
    vehicle_id: str
    v2_metrics: List[str] = Field(..., description="A list of available metric names from the V2 protocol cache.")
    v3_metrics: List[str] = Field(..., description="A list of available metric names from the live V3 MQTT data.")

class MetricsQueryRequest(BaseModel):
    metric_names: List[str] = Field(..., description="A list of metric names to query.", min_length=1, max_length=100)

class MetricsQueryResponse(BaseModel):
    vehicle_id: str
    metrics: Dict[str, Any] = Field(..., description="A dictionary of the requested metrics and their current values. Unavailable metrics will have a value of null.")
