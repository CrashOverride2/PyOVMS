# WebAuthn / Passkeys

← Back to [Production Setup, Step 4](../../Readme.md#step-4--passwordless--2fa-authentication-optional) · Variable reference: [Configuration](../CONFIGURATION.md#webauthn--passkeys)

PyOVMS supports passwordless and 2FA authentication using WebAuthn — hardware security keys (YubiKey, Titan Key) and device biometrics (Touch ID, Face ID, Windows Hello, Android fingerprint/face unlock).

> WebAuthn requires HTTPS in production. Development allows HTTP on `localhost`.

Users register their keys or biometrics at `/profile` → WebAuthn tab → "Register Security Key".

---

## Supported authentication flows

1. Username + Password
2. Username + Password + TOTP (authenticator app)
3. Username + Password + WebAuthn as 2FA (biometrics or security key)
4. Passwordless WebAuthn (biometrics or security key only)

---

## Step 1 — Configure `.env`

```dotenv
WEBAUTHN_RP_ID=yourdomain.com
WEBAUTHN_RP_NAME=My PyOVMS Server
WEBAUTHN_ORIGIN=https://yourdomain.com
```

For local development:

```dotenv
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=PyOVMS Dev
WEBAUTHN_ORIGIN=http://localhost:8000
```

---

## Step 2 — Configure `.well-known` files

These files allow mobile apps to associate your server with their app credentials, enabling passkey autofill and seamless login flows.

### iOS — Apple App Site Association

```bash
cd app/static/.well-known/
cp apple-app-site-association.example apple-app-site-association
```

Edit the file and replace the Team ID and Bundle ID:

```json
{
  "webcredentials": {
    "apps": [
      "A1B2C3D4E5.com.example.ovmsconnect"
    ]
  }
}
```

- **Team ID** — 10-character ID from Apple Developer → Membership
- **Bundle ID** — typically `com.example.ovmsconnect` for the official app

### Android — Digital Asset Links

```bash
cp assetlinks.json.example assetlinks.json
```

Edit the file and replace the package name and SHA-256 fingerprint:

```json
[{
  "relation": [
    "delegate_permission/common.handle_all_urls",
    "delegate_permission/common.get_login_creds"
  ],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.ovmsconnect",
    "sha256_cert_fingerprints": [
      "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
    ]
  }
}]
```

---

## Step 3 — Verify

Restart the server and confirm both endpoints return HTTP 200 with valid JSON:

```bash
curl https://yourdomain.com/.well-known/apple-app-site-association
curl https://yourdomain.com/.well-known/assetlinks.json
```

---

## Using the official OVMS Connect app

A mobile app can only complete a passkey ceremony for domains listed in its own
associated-domains configuration, which is baked into the signed app bundle. The official
app therefore ships with the maintainer's own instances pre-registered, and no other
domain will work until it is added there and a new build is released.

So for **your own** domain you have two options:

- **Use the web UI**, which works on any domain as soon as `WEBAUTHN_RP_ID` and
  `WEBAUTHN_ORIGIN` match it. Nothing else is required.
- **Contact the app maintainer** to have your domain added to the app's associated-domains
  list, and to obtain the app's signing credentials for your `.well-known` files.

The `.env` variables and `.well-known` files described above are what the server side
needs either way.
