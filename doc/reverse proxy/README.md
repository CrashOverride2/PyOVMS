# Reverse Proxy Setup

← Back to [Production Setup, Step 3](../../Readme.md#step-3--reverse-proxy-https)

Running PyOVMS behind a reverse proxy is strongly recommended for production. The proxy handles TLS termination, WebSocket forwarding, and acts as the single public entry point for all traffic.

This folder contains ready-to-use configs:

| File | Purpose |
|------|---------|
| `nginx.conf` | Nginx site config |
| `ssl.conf` | TLS hardening snippet (included by `nginx.conf`) |
| `Caddyfile` | Caddy site config (handles TLS automatically) |
| `404.html` … `504.html` | Custom error pages |

---

## Before you start

You need:
- A domain name with an A record pointing to your server's public IP
- PyOVMS running on port `8000`
- *(Optional)* Karto service on port `8001`
- *(Optional)* Valhalla routing container on port `8002`

---

## Step 1 — Install the error pages

Both proxy configs serve custom error pages from `/var/www/html/`. Copy them before starting the proxy:

```bash
sudo cp 404.html 429.html 502.html 504.html /var/www/html/
```

---

## Step 2 — Configure your proxy

Choose either Nginx or Caddy. Both cover the same PyOVMS feature set. Caddy is simpler because it manages TLS certificates automatically. Nginx is a good choice if you already run it or need fine-grained control.

### Option A — Nginx

```bash
# Install Nginx and Certbot
sudo apt install nginx certbot python3-certbot-nginx

# Obtain a TLS certificate
sudo certbot certonly --nginx -d your.domain.com

# Generate DH parameters (takes a few minutes — only needed once)
sudo openssl dhparam -out /etc/nginx/dhparams.pem 4096
sudo cp ssl.conf /etc/nginx/snippets/ssl.conf

# Install the site config
# Open nginx.conf and replace every occurrence of your.domain.com with your domain.
# Uncomment any optional service blocks (Valhalla, Karto, Protomaps) you intend to run.
sudo cp nginx.conf /etc/nginx/sites-available/pyovms
sudo ln -s /etc/nginx/sites-available/pyovms /etc/nginx/sites-enabled/pyovms

sudo nginx -t
sudo systemctl reload nginx
```

### Option B — Caddy

Caddy obtains and renews TLS certificates automatically — no Certbot step needed.

```bash
# Install Caddy
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# Install the site config
# Open Caddyfile and replace your.domain.com with your domain.
# Uncomment any optional service blocks you intend to run.
sudo cp Caddyfile /etc/caddy/Caddyfile

sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy obtains the TLS certificate automatically on the first incoming request.

---

## Step 3 — Update `.env`

Tell PyOVMS its public URL and that it should trust the local proxy for real client IPs:

```dotenv
SERVER_BASE_URL="https://your.domain.com"
FORWARDED_ALLOW_IPS="127.0.0.1"
```

```bash
sudo systemctl restart pyovms
```

---

## Optional services

Both config files contain commented blocks for optional services. Uncomment the relevant sections and reload the proxy after the service is running.

### Valhalla routing

Valhalla runs via Docker Compose and binds only to `127.0.0.1:8002` — it is never reachable directly from the internet. The proxy enforces API key authentication on every `/route` request by making an internal subrequest to PyOVMS's `/api/v1/auth/ping`.

```bash
# Place an OSM extract (.osm.pbf) in valhalla/custom_files/, then:
docker compose up -d valhalla
docker compose logs -f valhalla    # watch tile-building progress
```

Regional PBF extracts are available at [download.geofabrik.de](https://download.geofabrik.de).

### Karto trip tracking

The Karto service runs on port `8001` and is proxied under `/api/karto`. Enable it in `.env`:

```dotenv
ENABLE_KARTO_TRIP_TRACKING=true
```

### Protomaps tile server

Static `.pmtiles` files are served directly by the proxy from a local directory. The `Accept-Ranges` and `no-store` cache headers are required for correct range-request tile delivery.
