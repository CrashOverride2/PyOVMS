# PyOVMS — Python Open Vehicle Monitoring System Server

PyOVMS is a modern, Python-based server for the Open Vehicle Monitoring System (OVMS) V2 and V3 protocols. Built on FastAPI, it provides a clean web interface for real-time vehicle monitoring, management, and control.

![PyOVMS Dashboard](doc/PyOVMS_Main.jpg)

**Key capabilities at a glance:**
V2 (TCP) and V3 (MQTT) protocol support · Real-time WebSocket UI · Push notifications (NTFY / Email / FCM / APNs / UnifiedPush) · 2FA + WebAuthn/Passkeys · Rate limiting & security dashboard · Optional trip logging (Karto) · Optional charge session logging · Self-hosted maps (Protomaps) · SQLite / PostgreSQL / MySQL

→ See **[Vehicle Detail Page](doc/vehicle.md)** for UI screenshots and a feature walkthrough.
→ See **[Adding a Vehicle](doc/add_vehicle.md)** for the three-step setup wizard.

---

## Mobile App

PyOVMS is **fully compatible with the official OVMS apps over the V2 protocol** — they connect to a PyOVMS instance exactly as they would to any other OVMS server. The **OVMS Connect** app goes further: it subscribes to your vehicle over MQTT (V3) and uses the server's REST API for everything else, including all available metrics, charge logs and trip tracking.

[**Android — Google Play**](https://play.google.com/store/apps/details?id=com.CrashOverride.OVMS) · [**iOS — App Store**](https://apps.apple.com/us/app/ovms-connect/id6747955064)

---

## Public Server

Not everyone wants to run their own instance. **[turboserv.0-c.de](https://turboserv.0-c.de)** is the official public PyOVMS server, operated by the project maintainer — point your OVMS module and the OVMS Connect app at it and you are done, no hosting, no reverse proxy, no MQTT broker of your own.

What it stores and for how long is written down in the [privacy policy](https://turboserv.0-c.de/privacy).

---

## Who is this for?

Jump to the section that matches your goal:

| I want to… | Go to |
|---|---|
| Get a working server as fast as possible | [Quick Setup](#quick-setup) |
| Deploy properly in production | [Production Setup](#production-setup) |
| Contribute code or work on the project | [Development](#development) |
| Use a server without hosting one | [Public Server](#public-server) |
| Find a specific guide | [Documentation Map](#documentation-map) |


---

## Quick Setup

For people who want PyOVMS running locally or on a fresh Ubuntu server with minimal friction.

### Option A — Automated (Ubuntu 24.04)

One script installs Python, the FlashMQ MQTT broker, a dedicated system user, a virtual environment, auto-generated secrets, and a systemd service:

```bash
wget https://raw.githubusercontent.com/CrashOverride2/PyOVMS/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

Done. The service starts automatically. Check the journal for the first-run admin credentials:

```bash
sudo journalctl -u pyovms -n 50
```

The script installs to `/opt/PyOVMS`, runs the server as the `ovms` user, and configures FlashMQ for the V3 protocol — so [Step 2 of the production setup](#step-2--v3-protocol--mqtt) is already done for you.

### Option B — Manual (any platform)

```bash
git clone https://github.com/CrashOverride2/PyOVMS.git PyOVMS
cd PyOVMS
pip install -r requirements.txt
python run.py
```

On first start the server:
1. Creates a `.env` file from `.env-template` with cryptographically secure random secrets
2. Runs all database migrations automatically (SQLite by default — no setup needed)
3. Creates a temporary admin account and **prints the credentials to the console**

> ⚠️ Open `http://localhost:8000`, log in, and **change the admin username and password immediately** via the Profile page.

### Option C — Docker

Unlike the other two options, the `.env` must be **complete before the container starts**. Outside Docker, `run.py` fills in any missing secret by writing it into `.env`; in the container that file comes from the host and the unprivileged `ovms` user cannot patch it. `generate_secrets.py` produces a complete file, and the image itself can run it — so nothing has to be installed on the host:

```bash
# 1. Build first — the image doubles as the secret generator
docker build -t pyovms .

# 2. Write a complete .env (every secret, no placeholders left)
docker run --rm pyovms python doc/security/generate_secrets.py --show > .env
chmod 600 .env
```

Then set the database path in `.env` so the data survives the container:

```dotenv
DATABASE_URL="sqlite:////app/data/ovms_py.db"
```

```bash
# 3. Run — .env read-only, database on a named volume
docker run -d \
  --name pyovms \
  -p 8000:8000 \
  -p 6867:6867 \
  -p 6870:6870 \
  -v "$(pwd)/.env:/app/.env:ro" \
  -v pyovms-data:/app/data \
  pyovms

# 4. Read the first-run admin credentials
docker logs pyovms | grep -B2 -A6 CRITICAL
```

Do **not** use `--env-file` instead of the bind mount: Docker passes those values verbatim, quotes included, so `SERVER_BASE_URL` and friends arrive with literal `"` characters. For anything beyond a trial run, point `DATABASE_URL` at PostgreSQL — see [Step 1](#step-1--configure-env).

### Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| `8000` | HTTP | Web UI and API |
| `6867` | TCP | V2 plain-text |
| `6870` | TCP + TLS | V2 encrypted |
| `1883` | MQTT | V3 plain-text (broker, separate process) |
| `8883` | MQTT + TLS | V3 encrypted (broker, separate process) |

---

## Production Setup

For deploying PyOVMS on a public server with HTTPS, a real database, MQTT for V3 vehicles, and optional services.

If you used the [automated installer](#option-a--automated-ubuntu-2404), Steps 1 and 2 are already done — continue at [Step 3](#step-3--reverse-proxy-https).

### Step 1 — Configure `.env`

The `.env` file in the project root controls everything. A full reference of every variable is in **[Configuration](doc/CONFIGURATION.md)**. The most important settings to change from defaults:

```dotenv
DATABASE_URL="postgresql://user:password@localhost/pyovms"
SERVER_BASE_URL="https://your.domain.com"
FORWARDED_ALLOW_IPS="127.0.0.1"
```

Secrets are generated for you. `python run.py` generates every missing or placeholder secret on each start; `doc/security/generate_secrets.py` generates the JWT, TOTP and MQTT secrets up front, without starting the server:

```bash
python doc/security/generate_secrets.py
```

Already running on SQLite? See [Migrating SQLite → PostgreSQL](#migrating-sqlite--postgresql) below.

### Step 2 — V3 Protocol / MQTT

If your vehicles use the V3 (MQTT) protocol, PyOVMS needs a running MQTT broker and write access to its password and ACL files. PyOVMS manages the contents of these files automatically — you configure the paths once. Both **FlashMQ** (what the automated installer sets up) and **Mosquitto** are supported; the file formats are identical.

→ **[MQTT Setup Guide](doc/MQTT_SETUP.md)**

### Step 3 — Reverse Proxy (HTTPS)

Running behind Nginx or Caddy is strongly recommended. The `doc/reverse proxy/` folder contains ready-to-use configs for both, including TLS hardening, WebSocket proxying, custom error pages, and optional blocks for Karto, Protomaps and Valhalla.

Allow request bodies of at least 4 MB (`client_max_body_size 4m;` in Nginx): the app's configuration backups are JSON uploads of up to 256 K *characters*, which is up to 1 MiB of UTF-8 and up to three times that again if the client escapes non-ASCII text as `\uXXXX`.

→ **[Reverse Proxy Setup](doc/reverse%20proxy/README.md)**

### Step 4 — Passwordless / 2FA Authentication (optional)

Users can secure their accounts with TOTP (authenticator apps) or WebAuthn passkeys (Touch ID, Face ID, YubiKey, Windows Hello). Requires HTTPS in production.

→ **[WebAuthn / Passkeys Setup](doc/security/WEBAUTHN_SETUP.md)**

### Step 5 — Verify the deployment (optional)

Two checkers ship with the repo — a static one that needs no running server, and a live one that exercises the deployed instance:

```bash
bash doc/security/check_security.sh
python doc/security/test_security_features.py --url https://your.domain.com --password <admin-pw>
```

### Migrating SQLite → PostgreSQL

`doc/db_migrate_to_pg.load` is a [pgloader](https://pgloader.io/) command file that copies the data across. The schema is created by Alembic, not by pgloader — so the target database must already be migrated when you run it.

```bash
# 1. Stop the server so nothing writes to SQLite mid-copy
sudo systemctl stop pyovms

# 2. Back up the SQLite database and note the path
mkdir -p backups && cp ovms_py.db backups/ovms_py_to_migrate.db

# 3. Create the PostgreSQL database and user
sudo -u postgres createuser --pwprompt pyovms_user
sudo -u postgres createdb -O pyovms_user pyovms_db

# 4. Point .env at PostgreSQL
#    DATABASE_URL="postgresql://pyovms_user:<password>@localhost:5432/pyovms_db"

# 5. Create the empty schema with Alembic
alembic upgrade head

# 6. Edit the source path and connection string at the top of the command file,
#    then copy the data
pgloader doc/db_migrate_to_pg.load

# 7. Start the server and verify vehicles, users and charge logs are present
sudo systemctl start pyovms
```

### Production Checklist

- [ ] Database changed from SQLite to PostgreSQL
- [ ] `SERVER_BASE_URL` set to public HTTPS URL
- [ ] Secrets are not placeholder values (`bash doc/security/check_security.sh` verifies this)
- [ ] MQTT broker configured (if using V3 vehicles)
- [ ] Reverse proxy in front with valid TLS certificate
- [ ] `FORWARDED_ALLOW_IPS` set to the reverse proxy's address
- [ ] Admin password changed from the auto-generated first-run value
- [ ] Email configured (enables user registration, security alert emails to admins)
- [ ] `.env` is mode 0600 and excluded from backups that leave the host

---

## Development

For contributors and anyone who wants to modify the code, templates, or translations.

### Setup

```bash
git clone https://github.com/CrashOverride2/PyOVMS.git PyOVMS
cd PyOVMS
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, ruff, pip-audit

# Install Node.js deps for Tailwind CSS
npm install
```

`requirements.txt` is generated output — never edit it by hand. It is fully pinned and compiled from `requirements.in` with `uv`. Add new dependencies to `requirements.in`, then regenerate:

```bash
# Add or change a package, keeping every other pin where it is
uv pip compile requirements.in --universal --python-version 3.12 -o requirements.txt

# Pull in security fixes — re-resolves everything to the newest allowed
uv pip compile requirements.in --universal --python-version 3.12 --upgrade -o requirements.txt
```

`--universal` is not cosmetic: without it the resolution is specific to the machine that ran it. See the comments in `requirements-dev.txt` for the full reasoning.

### Run in development mode

In two terminals:

```bash
# Terminal 1 — server
python run.py

# Terminal 2 — watch and rebuild CSS on template changes
npm run watch
```

### Tests

```bash
pytest                # the default suite — offline and deterministic
pytest -m cve         # dependency CVE checks; queries the online advisory DB
```

### Database Migrations

```bash
# After changing a model, generate a migration
alembic revision --autogenerate -m "describe the change"

# Apply pending migrations
alembic upgrade head

# Roll back one step
alembic downgrade -1
```

Migrations run automatically on server startup — manual use of Alembic is only needed when creating or testing new migrations.

### Tailwind CSS

The pre-built CSS is committed to the repo. You only need to rebuild if you change template files or add new Tailwind classes.

```bash
npm run build   # one-time production build
npm run watch   # rebuild on every template save
```

→ **[Tailwind Setup](doc/tailwind_install.md)**

### Translations (i18n)

```bash
# 1. Extract, merge and compile — one command, pinned flags
scripts/update_translations.sh

# 2. Fill in any empty msgstr in app/translations/<lang>/LC_MESSAGES/messages.po

# 3. Run it again so the .mo files match
scripts/update_translations.sh
```

Use the script rather than calling `pybabel` directly: it pins the sort order, the
location format and the wrap column. Without them the catalog is rewritten wholesale on
every run, and a dropped translation is indistinguishable from the churn around it.

→ **[Translations Guide](doc/translations.md)**

---

## Documentation Map

Every document in this repository, and when you need it:

| Document | What it covers |
|---|---|
| [doc/CONFIGURATION.md](doc/CONFIGURATION.md) | Reference for every `.env` variable |
| [doc/MQTT_SETUP.md](doc/MQTT_SETUP.md) | V3 protocol: broker installation, password/ACL file handling |
| [doc/reverse proxy/README.md](doc/reverse%20proxy/README.md) | Nginx and Caddy configs, TLS, optional service blocks |
| [doc/security/WEBAUTHN_SETUP.md](doc/security/WEBAUTHN_SETUP.md) | Passkeys, hardware keys, app association files |
| [doc/vehicle.md](doc/vehicle.md) | Walkthrough of the vehicle detail page, tab by tab |
| [doc/add_vehicle.md](doc/add_vehicle.md) | Dashboard tour and the add-vehicle wizard |
| [doc/tailwind_install.md](doc/tailwind_install.md) | Building the CSS |
| [doc/translations.md](doc/translations.md) | Adding and updating UI languages |
| [privacy_policy.md](privacy_policy.md) | Privacy policy served at `/privacy` by the public instance |

---

## Credits

- **schorle** — Core & V2 protocol implementation

## License

Copyright (C) 2026 Carsten Schmiemann

PyOVMS is free software, licensed under the **GNU General Public License, version 3 only** ([`LICENSE`](LICENSE), [SPDX](https://spdx.org/licenses/GPL-3.0-only.html): `GPL-3.0-only`). It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Pointing the footer at your own source is therefore a courtesy rather than a duty — but a useful one, because users of your instance have no other way to find the code they are actually talking to:

```dotenv
SOURCE_CODE_URL="https://your.forge/your/pyovms-fork"
```

### Third-party components

PyOVMS bundles third-party code, all under licenses compatible with GPL-3.0:

| Component | License |
|---|---|
| Python dependencies (110 packages) | MIT, Apache-2.0, BSD, ISC, PSF |
| `psycopg2-binary` | LGPL with exceptions |
| `certifi` | MPL-2.0 |
| Leaflet, Leaflet.heat | BSD-2-Clause |
| pmtiles, protomaps-leaflet | BSD-3-Clause |
| Chart.js, Luxon, Alpine.js, Redoc, Tailwind CSS | MIT |
| `@msgpack/msgpack` | ISC |
| swagger-ui-dist | Apache-2.0 |
| Roboto Mono, Droid Sans Mono | Apache-2.0 |
