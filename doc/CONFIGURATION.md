# Configuration

← Back to [Production Setup, Step 1](../Readme.md#step-1--configure-env)

All configuration is managed through a `.env` file in the project root. On first start, `python run.py` generates this file from `.env-template` with cryptographically secure random secrets, and on every subsequent start it replaces any secret that is still missing or still a placeholder.

To create the file without starting the server:

```bash
python doc/security/generate_secrets.py
```

The result is a complete `.env` — every secret below is filled in, so the server needs no write access to it at runtime. That matters for containers, which mount the file read-only. See [Docker setup](../Readme.md#option-c--docker).

---

## Contents

- [Database](#database)
- [General Server](#general-server)
- [Security & Authentication](#security--authentication)
- [V3 Protocol / MQTT](#v3-protocol--mqtt)
- [V2 Protocol Compatibility](#v2-protocol-compatibility)
- [Notification Services](#notification-services)
- [Optional Integrations](#optional-integrations)
- [Web UI](#web-ui)
- [Internationalization](#internationalization)
- [Advanced TCP Settings](#advanced-tcp-settings)
- [Logging & Debugging](#logging--debugging)

---

## Database

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SQLAlchemy connection URL. PostgreSQL or MySQL recommended for production. | `"sqlite:///./ovms_py.db"` |

**Examples:**
- PostgreSQL: `postgresql://user:password@host:port/dbname`
- MySQL: `mysql+pymysql://user:password@host:port/dbname`

---

## General Server

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Listening address. `0.0.0.0` = all interfaces. | `"0.0.0.0"` |
| `HTTP_PORT` | Port for the Web UI and API. | `8000` |
| `TCP_PORT` | Port for plain V2 TCP protocol. | `6867` |
| `TCP_SSL_PORT` | Port for encrypted V2 TCP (requires `SSL_CERT_FILE` and `SSL_KEY_FILE`). | `6870` |
| `SERVER_BASE_URL` | Public-facing base URL. Required for correct links in outgoing emails. | `"http://localhost:8000"` |

---

## Security & Authentication

### Secrets

All secrets below are auto-generated on first start. Never leave a placeholder value in place in production — `bash doc/security/check_security.sh` flags any that are still set.

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY_JWT` | CSRF token signing key. 64-byte URL-safe random token. Local only — never copy it to another service. | Auto-generated |
| `SECRET_KEY_SESSION` | Signing key for the session cookie middleware. Local only — never copy it to another service. | Auto-generated |
| `JWT_PRIVATE_KEY` | Ed25519 private key (base64, 32 bytes) that signs session tokens. Keep on this host only. | Auto-generated |
| `JWT_PUBLIC_KEY` | Matching public key. This is the value the Karto service needs, so that it can verify sessions without being able to issue them. | Auto-generated |
| `TOTP_ENCRYPTION_KEY` | Fernet key for encrypting 2FA secrets at rest. | Auto-generated |

The two halves of the JWT key pair are always regenerated together — replacing only one would make every existing session fail to verify.

To regenerate manually:
```bash
# JWT secret
openssl rand -base64 64

# TOTP key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Registration & Email Verification

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOW_USER_REGISTRATION` | Allow self-registration via the web UI. Requires email to be configured. | `False` |
| `SEND_ADMIN_REGISTRATION_EMAIL` | Email all admins when a new user registers. | `True` |
| `EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS` | How long a verification link stays valid. | `24` |
| `FORWARDED_ALLOW_IPS` | Trust `X-Forwarded-*` headers from these proxy IPs. | `"127.0.0.1"` |

### Rate Limiting & IP Blocking

Rate limiting is always active and cannot be disabled.

| Event | Threshold | Consequence |
|-------|-----------|-------------|
| Login failures | 5 in 60 seconds | 60-minute IP block |
| API key failures | 10 in 60 seconds | 60-minute IP block |
| TOTP failures | 5 attempts | Temporary IP block |
| TOTP failures | 10 attempts | Permanent account lockout (admin intervention required) |

The Security Events Dashboard at `/admin/security-events` shows blocked IPs, event counts by severity, and a filterable log with time-range selection. When an IP is blocked, all active admins receive an email alert.

### Multi-Factor Authentication (TOTP)

Users enable 2FA in their profile by scanning a QR code with any TOTP app (Google Authenticator, Authy, 1Password, etc.). TOTP secrets are encrypted in the database using `TOTP_ENCRYPTION_KEY`.

### WebAuthn / Passkeys

Passwordless and 2FA authentication using hardware keys (YubiKey, Titan Key) or device biometrics (Touch ID, Face ID, Windows Hello, Android fingerprint/face unlock). Requires HTTPS in production.

→ **[WebAuthn Setup Guide](security/WEBAUTHN_SETUP.md)**

---

## V3 Protocol / MQTT

V3 support is enabled by setting **both** `MQTT_PASSWD_FILE` and `MQTT_ACL_FILE` — with either one unset the broker credential sync is switched off and no V3 vehicle can connect. MQTT backend passwords are auto-generated on first start. FlashMQ and Mosquitto are both supported; the file formats are identical.

| Variable | Description | Default |
|----------|-------------|---------|
| `MQTT_BROKER_HOST` | Hostname or IP of the MQTT broker. | `"localhost"` |
| `MQTT_BROKER_PORT` | MQTT broker port (non-TLS). | `1883` |
| `MQTT_PASSWD_FILE` | Absolute path to the password file PyOVMS manages for the broker. Must be writable by the PyOVMS user. | `None` |
| `MQTT_ACL_FILE` | Absolute path to the ACL file PyOVMS manages for the broker. Must be writable by the PyOVMS user. | `None` |
| `MQTT_BACKEND_METRICS_SUB_USER` | Username for the metrics subscriber client. | `"pyovms_metrics_sub"` |
| `MQTT_BACKEND_METRICS_SUB_PASS` | Password for the metrics subscriber. | Auto-generated |
| `MQTT_BACKEND_NOTIFY_SUB_USER` | Username for the notification subscriber client. | `"pyovms_notify_sub"` |
| `MQTT_BACKEND_NOTIFY_SUB_PASS` | Password for the notification subscriber. | Auto-generated |
| `MQTT_BACKEND_INTERACTIVE_USER` | Username for the interactive command client. | `"pyovms_interactive"` |
| `MQTT_BACKEND_INTERACTIVE_PASS` | Password for the interactive client. | Auto-generated |

→ **[MQTT Setup Guide](MQTT_SETUP.md)**

---

## V2 Protocol Compatibility

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOW_FCM_TOKEN_FROM_V2` | Accept FCM (Android) tokens from legacy V2 clients. | `True` |
| `ALLOW_APNS_TOKEN_FROM_V2` | Accept APNs (iOS) tokens from V2 clients. | `False` |

---

## Notification Services

All settings here are global defaults. Most can be overridden per vehicle in the web UI.

### NTFY

| Variable | Description | Default |
|----------|-------------|---------|
| `NTFY_SERVER` | NTFY server URL. | `"https://ntfy.sh"` |
| `NTFY_DEFAULT_TOPIC` | Default topic if not set per vehicle. | `"ovms_alerts_python"` |
| `NTFY_AUTH_METHOD` | `"bearer"`, `"basic"`, `"query"`, or `"none"`. | `None` |
| `NTFY_AUTH_TOKEN` | Token for bearer or query auth. | `None` |
| `NTFY_AUTH_USER` | Username for basic auth. | `None` |
| `NTFY_AUTH_PASSWORD` | Password for basic auth. | `None` |
| `NTFY_AUTH_QUERY_PARAM_NAME` | Query parameter name for query auth. | `"token"` |

### Email

Required for user registration and security alert emails to admins.

| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_HOST` | SMTP server hostname or IP. | `None` |
| `EMAIL_PORT` | SMTP port. | `587` |
| `EMAIL_USE_TLS` | Use STARTTLS. | `True` |
| `EMAIL_USE_SSL` | Use SSL-wrapped connection. | `False` |
| `EMAIL_USERNAME` | SMTP username. | `None` |
| `EMAIL_PASSWORD` | SMTP password. | `None` |
| `EMAIL_SENDER` | "From" address for outgoing emails. | `None` |

Security alert emails go to all active admin users with an email address in their profile — no separate `ADMIN_EMAIL` setting is needed.

### FCM (Android)

| Variable | Description | Default |
|----------|-------------|---------|
| `FCM_CREDENTIALS_PATH` | Path to Firebase Admin SDK service account JSON key. | `None` |

### APNs (iOS)

| Variable | Description | Default |
|----------|-------------|---------|
| `APNS_AUTH_KEY_PATH` | Path to `.p8` private key from Apple Developer portal. | `None` |
| `APNS_KEY_ID` | 10-character Key ID from Apple Developer portal. | `None` |
| `APNS_TEAM_ID` | 10-character Apple Developer Team ID. | `None` |
| `APNS_TOPIC` | App bundle ID (e.g. `com.openvehicles.ios`). | `None` |
| `APNS_SERVER_MODE` | `"production"` or `"development"`. | `"production"` |
| `APNS_DELIVERY_METHOD` | `"apns"` (native gateway) or `"fcm"` (route through Firebase). | `"apns"` |

---

## Optional Integrations

### Karto Trip Tracking

Karto is a **separate service with its own repository and process**, reached through the reverse proxy at `/api/karto/`. It shares this server's database and verifies session cookies with `JWT_PUBLIC_KEY`. See [Reverse Proxy Setup](reverse%20proxy/README.md#karto-trip-tracking) for wiring it up.

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_KARTO_TRIP_TRACKING` | Merges Karto's API documentation into this server's `/docs`, and enables the trip UI. Does **not** start the Karto service. Requires MQTT. | `False` |
| `KARTO_MQTT_USER` | Karto MQTT client username. | `"karto_service_user"` |
| `KARTO_MQTT_PASSWORD` | Karto MQTT client password. | Auto-generated |

### Charge Logging

Enabled per vehicle in its settings, not globally.

| Variable | Description | Default |
|----------|-------------|---------|
| `TIMEOUT_CHARGE_IDLE` | Seconds before a stale charge session is marked complete. | `1800` |

### Protomaps (Self-Hosted Maps)

| Variable | Description | Default |
|----------|-------------|---------|
| `PROTOMAPS_URL` | URL to a `.pmtiles` file. Falls back to OpenStreetMap if unset. | `None` |

---

## Web UI

| Variable | Description | Default |
|----------|-------------|---------|
| `SOURCE_CODE_URL` | Target of the "Source Code" link in the page footer. GPL-3.0 has no network clause, so this is a courtesy rather than an obligation — but if you modified PyOVMS, point it at your own repository so users of your instance can find the code they are talking to. | upstream repo |
| `FIRMWARE_REPO_URL` | Optional footer link to a firmware mirror. Hidden while unset. | unset |
| `DONATION_URL` | Optional footer link to a donation page. Hidden while unset. | unset |

---

## Internationalization

| Variable | Description | Default |
|----------|-------------|---------|
| `BABEL_DEFAULT_LOCALE` | Default UI language (e.g. `"en"`, `"de"`). | `"en"` |
| `SUPPORTED_LOCALES` | Comma-separated list of supported locales. | `["en", "de", "fr", "es"]` |
| `BABEL_TRANSLATION_DIRECTORIES` | Path to translation files relative to project root. | `"app/translations"` |

→ **[Translations Guide](translations.md)**

---

## Advanced TCP Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `SSL_CERT_FILE` | SSL certificate for the encrypted V2 TCP port. | `"cert.pem"` |
| `SSL_KEY_FILE` | SSL private key for the encrypted V2 TCP port. | `"key.pem"` |
| `TIMEOUT_CAR_IDLE` | Seconds before an idle car connection is dropped. | `960` |
| `TIMEOUT_APP_IDLE` | Seconds before an idle app connection is dropped. | `1200` |
| `TIMEOUT_TCP_INITIAL_AUTH` | Seconds a new connection has to complete the handshake. | `60` |
| `TCP_IDLE_CHECK_INTERVAL` | How often (in seconds) the server checks for idle connections. | `60` |
| `TCP_SERVER_PING_INTERVAL` | Seconds of car idle before the server sends a keepalive ping. | `60` |
| `TCP_KEEPIDLE` | OS TCP keepalive: idle time before probes start. Platform-dependent. | `240` |
| `TCP_KEEPINTVL` | OS TCP keepalive: interval between probes. Platform-dependent. | `240` |
| `TCP_KEEPCNT` | OS TCP keepalive: number of probes before the connection is dropped. | `9` |

---

## Logging & Debugging

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. | `"INFO"` |
| `LOG_FILE` | Path to the log file. Empty string disables file logging. | `"pyovms_control.log"` |
| `DEBUG_TCP_PACKETS` | Log all V2 TCP packets in decrypted form. Very verbose — do not use in production. | `False` |
| `LOG_HISTORY_DAYS` | Days to keep historical data (location, status) before automatic pruning. | `7` |
