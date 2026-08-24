#!/bin/bash
# PyOVMS Security Check Script
# Run from the project root: bash doc/security/check_security.sh
#
# Static / configuration checks only — no running server required.
# For live HTTP tests, see: python doc/security/test_security_features.py

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# ── Colour helpers ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; WARN=0; FAIL=0

ok()      { echo -e "${GREEN}  ✓${NC} $*"; ((PASS++)) || true; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $*"; ((WARN++)) || true; }
fail()    { echo -e "${RED}  ✗${NC} $*"; ((FAIL++)) || true; }
info()    { echo -e "${CYAN}  ℹ${NC} $*"; }
section() { echo; echo -e "${BOLD}$*${NC}"; echo "$(printf '─%.0s' {1..60})"; }

echo -e "${BOLD}PyOVMS Security Check${NC}"
echo "======================================================================"
echo "Project: $PROJECT_ROOT"
echo "Date:    $(date '+%Y-%m-%d %H:%M %Z')"
echo "======================================================================"


# ── 1. Python version ───────────────────────────────────────────────────────────
section "1. Python Runtime"
PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 12 ]]; then
    ok "Python $PY_VER (supported)"
elif [[ "$PY_MAJOR" -ge 3 && "$PY_MINOR" -ge 10 ]]; then
    warn "Python $PY_VER – functional but requirements.txt is compiled for 3.12"
else
    fail "Python $PY_VER – unsupported, upgrade to 3.12"
fi


# ── 2. Dependency vulnerabilities ──────────────────────────────────────────────
section "2. Dependency Vulnerabilities"

if command -v pip-audit &>/dev/null; then
    AUDIT_OUT=$(pip-audit --desc 2>&1 || true)
    if echo "$AUDIT_OUT" | grep -q "No known vulnerabilities"; then
        ok "No known CVEs in installed packages (pip-audit)"
    else
        CVE_COUNT=$(echo "$AUDIT_OUT" | grep -c "^[A-Z]" 2>/dev/null || echo "?")
        fail "Vulnerabilities detected – run: pip-audit --desc"
    fi
else
    warn "pip-audit not installed – run: pip install pip-audit"
fi

# Bandit SAST scan
if command -v bandit &>/dev/null; then
    BANDIT_OUT=$(bandit -r app/ -ll -q 2>&1 || true)
    HIGH=$(echo "$BANDIT_OUT" | grep -c "Severity: High" 2>/dev/null || echo 0)
    MED=$(echo "$BANDIT_OUT"  | grep -c "Severity: Medium" 2>/dev/null || echo 0)
    if [[ "$HIGH" -gt 0 ]]; then
        fail "Bandit found $HIGH high-severity issue(s) in app/ – run: bandit -r app/ -ll"
    elif [[ "$MED" -gt 0 ]]; then
        warn "Bandit found $MED medium-severity issue(s) in app/ – run: bandit -r app/ -ll"
    else
        ok "Bandit SAST: no high/medium findings in app/"
    fi
else
    warn "bandit not installed – run: pip install bandit  (static security analysis)"
fi

# Outdated packages
OUTDATED=$( { pip list --outdated --format=freeze 2>/dev/null || true; } | wc -l | tr -d ' ')
if [[ "$OUTDATED" -gt 0 ]]; then
    warn "$OUTDATED package(s) outdated – run: pip list --outdated"
else
    ok "All installed packages are up-to-date"
fi


# ── 3. .env file ───────────────────────────────────────────────────────────────
section "3. Environment File (.env)"

if [[ ! -f ".env" ]]; then
    fail ".env file missing – run: python run.py  to auto-generate it"
else
    ok ".env file exists"

    # Permissions
    if [[ "$(uname)" == "Darwin" ]]; then
        PERMS=$(stat -f "%A" .env)
    else
        PERMS=$(stat -c "%a" .env 2>/dev/null || echo "unknown")
    fi
    if [[ "$PERMS" == "600" || "$PERMS" == "400" ]]; then
        ok ".env permissions: $PERMS (secure)"
    elif [[ "$PERMS" == "unknown" ]]; then
        warn "Could not determine .env permissions – ensure it is chmod 600"
    else
        warn ".env permissions: $PERMS (should be 600) – fix: chmod 600 .env"
    fi

    # ── Placeholder / default secrets ──────────────────────────────────────────
    DEFAULT_FOUND=()
    grep -qE '^[^#]*change_this_for_production'                      .env 2>/dev/null && DEFAULT_FOUND+=("SECRET_KEY_JWT / SECRET_KEY_SESSION")
    grep -qE '^[^#]*0gXIqS9Z0kZ-Yg7tJ2eX_rU8wH6vI9nL0fA3cE1bS2k='  .env 2>/dev/null && DEFAULT_FOUND+=("TOTP_ENCRYPTION_KEY")
    grep -qE '^[^#]*changeme_(metrics|notify|interactive)' .env 2>/dev/null && DEFAULT_FOUND+=("MQTT_BACKEND_*_PASS")
    grep -qE '^[^#]*a_very_strong_mqtt_password_for_karto'            .env 2>/dev/null && DEFAULT_FOUND+=("KARTO_MQTT_PASSWORD")

    if [[ ${#DEFAULT_FOUND[@]} -gt 0 ]]; then
        fail "Default/placeholder secrets still present: ${DEFAULT_FOUND[*]}"
        info "Fix: python run.py auto-replaces them on next start"
    else
        ok "No default placeholder secrets detected"
    fi

    # ── JWT key strength ────────────────────────────────────────────────────────
    JWT_VAL=$(grep '^SECRET_KEY_JWT=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ ${#JWT_VAL} -ge 64 ]]; then
        ok "SECRET_KEY_JWT length: ${#JWT_VAL} chars (strong)"
    elif [[ ${#JWT_VAL} -ge 32 ]]; then
        warn "SECRET_KEY_JWT length: ${#JWT_VAL} chars – 64+ chars recommended"
    elif [[ -n "$JWT_VAL" ]]; then
        fail "SECRET_KEY_JWT too short (${#JWT_VAL} chars) – regenerate with ≥64 chars"
    fi

    # ── Session key strength ────────────────────────────────────────────────────
    SESSION_VAL=$(grep '^SECRET_KEY_SESSION=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ ${#SESSION_VAL} -ge 32 ]]; then
        ok "SECRET_KEY_SESSION length: ${#SESSION_VAL} chars (adequate)"
    elif [[ -n "$SESSION_VAL" ]]; then
        fail "SECRET_KEY_SESSION too short (${#SESSION_VAL} chars) – regenerate"
    fi

    # ── TOTP key: valid Fernet format ───────────────────────────────────────────
    TOTP_VAL=$(grep '^TOTP_ENCRYPTION_KEY=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ -n "$TOTP_VAL" ]]; then
        if python3 -c "from cryptography.fernet import Fernet; Fernet('${TOTP_VAL}'.encode())" 2>/dev/null; then
            ok "TOTP_ENCRYPTION_KEY is a valid Fernet key"
        else
            fail "TOTP_ENCRYPTION_KEY is not a valid Fernet key – regenerate: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        fi
    fi

    # ── JWT lifetime ────────────────────────────────────────────────────────────
    TOKEN_EXP=$(grep '^ACCESS_TOKEN_EXPIRE_MINUTES=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ -n "$TOKEN_EXP" ]]; then
        if [[ "$TOKEN_EXP" -le 60 ]]; then
            ok "ACCESS_TOKEN_EXPIRE_MINUTES: $TOKEN_EXP (≤ 60 min – good)"
        elif [[ "$TOKEN_EXP" -le 480 ]]; then
            warn "ACCESS_TOKEN_EXPIRE_MINUTES: $TOKEN_EXP (>60 min – consider reducing to ≤60)"
        else
            fail "ACCESS_TOKEN_EXPIRE_MINUTES: $TOKEN_EXP (>8 hours – too long, set ≤60)"
        fi
    else
        info "ACCESS_TOKEN_EXPIRE_MINUTES not set – using default (60 min)"
    fi

    # ── Secure cookies ──────────────────────────────────────────────────────────
    if grep -qiE '^FORCE_SECURE_COOKIES\s*=\s*(true|1)' .env 2>/dev/null; then
        ok "FORCE_SECURE_COOKIES is enabled"
    else
        warn "FORCE_SECURE_COOKIES not True – required for production HTTPS deployments"
    fi

    # ── WebAuthn RP_ID should not be localhost in production ────────────────────
    RPID=$(grep '^WEBAUTHN_RP_ID=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ -n "$RPID" ]]; then
        if echo "$RPID" | grep -qE '^localhost$|^127\.'; then
            warn "WEBAUTHN_RP_ID is '$RPID' – update to your production domain"
        else
            ok "WEBAUTHN_RP_ID: $RPID"
        fi
    fi

    # ── WebAuthn origin should use HTTPS in production ──────────────────────────
    WA_ORIGIN=$(grep '^WEBAUTHN_ORIGIN=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ -n "$WA_ORIGIN" ]]; then
        if echo "$WA_ORIGIN" | grep -q '^http://localhost'; then
            warn "WEBAUTHN_ORIGIN is '$WA_ORIGIN' – update to https://yourdomain for production"
        elif echo "$WA_ORIGIN" | grep -q '^http://'; then
            fail "WEBAUTHN_ORIGIN uses plain http:// – WebAuthn requires HTTPS in production"
        else
            ok "WEBAUTHN_ORIGIN: $WA_ORIGIN"
        fi
    fi

    # ── Trusted proxy IPs (should not be wildcard) ──────────────────────────────
    FWDIPS=$(grep '^FORWARDED_ALLOW_IPS=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if [[ -n "$FWDIPS" ]]; then
        if echo "$FWDIPS" | grep -qE '^\*|^0\.0\.0\.0'; then
            fail "FORWARDED_ALLOW_IPS='$FWDIPS' – wildcard trusts any proxy, set to your actual reverse proxy IP"
        else
            ok "FORWARDED_ALLOW_IPS: $FWDIPS"
        fi
    else
        info "FORWARDED_ALLOW_IPS not set – defaults to 127.0.0.1 (secure)"
    fi

    # ── SERVER_BASE_URL ─────────────────────────────────────────────────────────
    BASE_URL=$(grep '^SERVER_BASE_URL=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if echo "$BASE_URL" | grep -qE 'localhost|127\.0\.0\.1'; then
        warn "SERVER_BASE_URL is '$BASE_URL' – update to your production URL"
    elif [[ -n "$BASE_URL" ]]; then
        ok "SERVER_BASE_URL: $BASE_URL"
    fi

    # ── Database backend ────────────────────────────────────────────────────────
    DB_URL=$(grep '^DATABASE_URL=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r')
    if echo "$DB_URL" | grep -q 'sqlite'; then
        warn "DATABASE_URL uses SQLite – fine for single-node; use PostgreSQL/MySQL for HA"
    elif [[ -n "$DB_URL" ]]; then
        ok "DATABASE_URL: ${DB_URL%%:*} (non-SQLite)"
    fi

    # ── Debug mode ──────────────────────────────────────────────────────────────
    if grep -qiE '^DEBUG\s*=\s*(true|1|yes)' .env 2>/dev/null; then
        fail "DEBUG=True in .env – disable for production"
    else
        ok "DEBUG mode not enabled"
    fi

    # ── User registration open? ─────────────────────────────────────────────────
    if grep -qiE '^ALLOW_USER_REGISTRATION\s*=\s*(true|1)' .env 2>/dev/null; then
        warn "ALLOW_USER_REGISTRATION=True – open registration enabled; intentional?"
    else
        ok "User self-registration is disabled (ALLOW_USER_REGISTRATION not set to True)"
    fi
fi


# ── 4. .gitignore ──────────────────────────────────────────────────────────────
section "4. .gitignore"

if [[ -f ".gitignore" ]]; then
    if grep -qE '^\.env$' .gitignore; then
        ok ".env is listed in .gitignore"
    else
        fail ".env is NOT in .gitignore – risk of committing secrets!"
        info "Fix: echo '.env' >> .gitignore"
    fi

    if grep -qE '\.log' .gitignore; then
        ok "Log files excluded from git"
    else
        warn "Log files may not be excluded – add *.log to .gitignore"
    fi

    for SECRET_FILE in cert.pem key.pem; do
        if ! grep -q "$SECRET_FILE" .gitignore; then
            warn "$SECRET_FILE not in .gitignore – SSL keys should never be committed"
        fi
    done
else
    warn ".gitignore not found"
fi

# .env must not be tracked by git
if git ls-files --error-unmatch .env &>/dev/null 2>&1; then
    fail ".env is tracked by git! Remove it: git rm --cached .env && git commit"
else
    ok ".env is not tracked by git"
fi

# Ensure no secrets leaked in git history (basic check)
if git log --oneline --all --diff-filter=A -- .env 2>/dev/null | grep -q .; then
    warn ".env was committed at some point in git history – consider: git filter-repo"
fi


# ── 5. SSL / TLS Certificates ──────────────────────────────────────────────────
section "5. SSL / TLS Certificates"

CERT_FILE=$(grep '^SSL_CERT_FILE=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r' || true)
KEY_FILE=$(grep '^SSL_KEY_FILE=' .env 2>/dev/null | cut -d= -f2- | tr -d '"'"'" | tr -d '\r' || true)
CERT_FILE="${CERT_FILE:-cert.pem}"
KEY_FILE="${KEY_FILE:-key.pem}"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    ok "SSL cert ($CERT_FILE) and key ($KEY_FILE) found"

    # Key file permissions
    if [[ "$(uname)" == "Darwin" ]]; then
        KEY_PERMS=$(stat -f "%A" "$KEY_FILE")
    else
        KEY_PERMS=$(stat -c "%a" "$KEY_FILE" 2>/dev/null || echo "unknown")
    fi
    if [[ "$KEY_PERMS" == "600" || "$KEY_PERMS" == "400" ]]; then
        ok "SSL key permissions: $KEY_PERMS (secure)"
    else
        warn "SSL key permissions: $KEY_PERMS – should be 600: chmod 600 $KEY_FILE"
    fi

    # Certificate expiry
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -n "$EXPIRY" ]]; then
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -jf "%b %d %H:%M:%S %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [[ $DAYS_LEFT -lt 0 ]]; then
            fail "SSL certificate EXPIRED ($DAYS_LEFT days ago) – renew immediately"
        elif [[ $DAYS_LEFT -lt 14 ]]; then
            fail "SSL certificate expires in $DAYS_LEFT day(s) – renew now"
        elif [[ $DAYS_LEFT -lt 30 ]]; then
            warn "SSL certificate expires in $DAYS_LEFT day(s) – schedule renewal"
        else
            ok "SSL certificate valid for $DAYS_LEFT more days"
        fi
    fi

    # Minimum key size
    KEY_BITS=$(openssl x509 -noout -text -in "$CERT_FILE" 2>/dev/null | grep -oP 'Public-Key: \(\K[0-9]+' | head -1)
    if [[ -n "$KEY_BITS" ]]; then
        if [[ "$KEY_BITS" -ge 2048 ]]; then
            ok "Certificate key size: ${KEY_BITS} bit"
        else
            fail "Certificate key size: ${KEY_BITS} bit – use ≥2048-bit RSA or P-256 ECDSA"
        fi
    fi
else
    warn "SSL cert/key not found at $CERT_FILE / $KEY_FILE"
    info "TCP SSL port (6870) will be disabled; ensure TLS is terminated by reverse proxy"
fi


# ── 6. Code-Level Security Checks ──────────────────────────────────────────────
section "6. Code Quick-Checks"

# Hardcoded secrets in Python source (excluding known safe patterns)
HARDCODED=$(grep -rn --include="*.py" \
    -e "SECRET_KEY.*=.*['\"][a-zA-Z0-9_\-]\{20,\}['\"]" \
    -e "password.*=.*['\"][a-zA-Z0-9_\-]\{8,\}['\"]" \
    app/ 2>/dev/null \
    | grep -v -E '#|config\.|_default|changeme|placeholder|example|secret_initializer|generate_secrets|settings\.|PASSWORD_REGEX|pwd_context|ERROR_MESSAGE' \
    | head -5 || true)
if [[ -n "$HARDCODED" ]]; then
    warn "Possible hardcoded secrets in source – review:"
    echo "$HARDCODED" | while IFS= read -r line; do info "  $line"; done
else
    ok "No obvious hardcoded secrets in app/"
fi

# SQL injection: raw string formatting inside execute()
SQLI=$(set +o pipefail; grep -rn --include="*.py" \
    -E "execute\s*\(.*(%[sf]|\+|\.format\()" \
    app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$SQLI" -gt 0 ]]; then
    warn "$SQLI potential raw-SQL format strings found – review for injection risk"
else
    ok "No string-formatted SQL queries detected"
fi

# subprocess calls (potential command injection)
SUBPROC=$(set +o pipefail; grep -rn --include="*.py" \
    -E "subprocess\.(run|call|check_output|Popen|getoutput)\s*\(" \
    app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$SUBPROC" -gt 0 ]]; then
    warn "$SUBPROC subprocess call(s) found – verify none use unsanitized user input"
    grep -rn --include="*.py" -E "subprocess\.(run|call|check_output|Popen|getoutput)" app/ 2>/dev/null | grep -v '#' || true
else
    ok "No subprocess calls detected in app/"
fi

# eval() / exec() usage
EVAL=$(set +o pipefail; grep -rn --include="*.py" -E "\beval\s*\(|\bexec\s*\(" app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$EVAL" -gt 0 ]]; then
    fail "$EVAL eval/exec call(s) found – potential code injection risk:"
    grep -rn --include="*.py" -E "\beval\s*\(|\bexec\s*\(" app/ 2>/dev/null | grep -v '#' || true
else
    ok "No eval/exec calls in app/"
fi

# pickle usage (deserialization risk)
PICKLE=$(set +o pipefail; grep -rn --include="*.py" -E "\bpickle\b" app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$PICKLE" -gt 0 ]]; then
    warn "$PICKLE pickle reference(s) found – unsafe for untrusted data"
else
    ok "No pickle usage detected"
fi

# | safe Jinja2 filter applied to variables (potential stored XSS)
JINJA_SAFE=$(set +o pipefail; grep -rn --include="*.html" \
    -E "\{\{[^}]*\|\s*safe" \
    app/templates/ 2>/dev/null | grep -v '<!-' | wc -l | tr -d ' ')
if [[ "$JINJA_SAFE" -gt 0 ]]; then
    warn "$JINJA_SAFE Jinja2 '| safe' usage(s) in templates – verify none render user content:"
    grep -rn --include="*.html" -E "\{\{[^}]*\|\s*safe" app/templates/ 2>/dev/null | grep -v '<!-' | head -10 || true
else
    ok "No Jinja2 '| safe' filter on template expressions"
fi

# unsafe-eval in CSP (should not be present in production code)
CSP_EVAL=$(set +o pipefail; grep -rn --include="*.py" "unsafe-eval" app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$CSP_EVAL" -gt 0 ]]; then
    fail "$CSP_EVAL 'unsafe-eval' reference(s) in app/ – CSP weakened:"
    grep -rn --include="*.py" "unsafe-eval" app/ 2>/dev/null | grep -v '#' || true
else
    ok "No 'unsafe-eval' in CSP definitions"
fi

# unsafe-inline in CSP Python code (nonce-based approach preferred)
CSP_INLINE=$(set +o pipefail; grep -rn --include="*.py" "unsafe-inline" app/ 2>/dev/null | grep -v '#' | wc -l | tr -d ' ')
if [[ "$CSP_INLINE" -gt 0 ]]; then
    warn "$CSP_INLINE 'unsafe-inline' reference(s) in CSP – ensure nonce is used instead:"
    grep -rn --include="*.py" "unsafe-inline" app/ 2>/dev/null | grep -v '#'
else
    ok "No 'unsafe-inline' in CSP definitions"
fi


# ── 7. Security Features Status ────────────────────────────────────────────────
section "7. Security Features — Implementation Checks"

# JWT library: must use PyJWT (not hand-rolled)
if grep -rn --include="*.py" "import jwt" app/security.py 2>/dev/null | grep -qv '#'; then
    ok "JWT: PyJWT library in use (app/security.py)"
else
    warn "Could not confirm PyJWT usage in app/security.py"
fi

# CSRF protection present
if grep -rn --include="*.py" "verify_csrf_token" app/routers/ 2>/dev/null | grep -qv '#'; then
    ok "CSRF: verify_csrf_token calls found in routers"
else
    fail "CSRF: no verify_csrf_token calls found – check CSRF is enforced on all mutating routes"
fi

# Rate limiter in SecurityManager
if grep -q "security_manager" app/main.py 2>/dev/null; then
    ok "Rate limiting: SecurityMiddleware references security_manager in main.py"
else
    warn "SecurityMiddleware not detected in main.py"
fi

# Password strength validator
if grep -q "PASSWORD_REGEX" app/models/api.py 2>/dev/null; then
    ok "Password policy: PASSWORD_REGEX strength check in api.py"
else
    warn "Password strength policy not found in app/models/api.py"
fi

# TOTP replay cache
if grep -q "_used_totp_codes" app/security.py 2>/dev/null; then
    ok "TOTP replay prevention: _used_totp_codes cache present in security.py"
else
    warn "TOTP replay prevention not detected in app/security.py"
fi

# Token version check
if grep -q "token_version" app/security.py 2>/dev/null; then
    ok "JWT token invalidation: token_version check in security.py"
else
    warn "Token version invalidation not detected in app/security.py"
fi

# Security headers middleware
if grep -q "SecurityHeadersMiddleware" app/main.py 2>/dev/null; then
    ok "Security headers: SecurityHeadersMiddleware registered in main.py"
else
    fail "SecurityHeadersMiddleware not found in main.py"
fi

# NTFY SSRF protection
if grep -q "_validate_ntfy_server_url" app/models/api.py 2>/dev/null; then
    ok "NTFY SSRF protection: _validate_ntfy_server_url validator in models/api.py"
else
    fail "NTFY SSRF protection not found – check app/models/api.py"
fi

# UnifiedPush endpoint SSRF protection
if grep -q "_validate_push_endpoint_url" app/models/api.py 2>/dev/null; then
    ok "UnifiedPush SSRF protection: _validate_push_endpoint_url validator present"
else
    warn "UnifiedPush endpoint URL validation not detected in app/models/api.py"
fi

# Server header removal
if grep -q "RemoveServerHeaderMiddleware" app/main.py 2>/dev/null; then
    ok "Server header: RemoveServerHeaderMiddleware registered (hides server version)"
else
    warn "RemoveServerHeaderMiddleware not found in main.py – consider hiding Server header"
fi

# WebSocket one-time ticket auth
if grep -rn --include="*.py" "ws_ticket\|ws_auth_ticket" app/ 2>/dev/null | grep -qv '#'; then
    ok "WebSocket auth: one-time ticket mechanism found"
else
    warn "WebSocket ticket auth pattern not found – verify WS connections require auth"
fi

# X-Forwarded-For trusted proxy enforcement
if grep -q "FORWARDED_ALLOW_IPS\|trusted_hosts\|get_client_ip" app/dependencies.py 2>/dev/null || \
   grep -q "FORWARDED_ALLOW_IPS" app/config.py 2>/dev/null; then
    ok "Trusted proxy enforcement: FORWARDED_ALLOW_IPS / get_client_ip found"
else
    warn "Trusted proxy IP check not clearly detected"
fi

# alg:none prevention in JWT decode
if grep -q 'algorithms=\[' app/security.py 2>/dev/null; then
    ok "JWT alg:none prevention: explicit algorithms=[] allowlist in security.py"
else
    fail "JWT decode does not specify explicit algorithms list – vulnerable to alg:none attack"
fi

# bcrypt password hashing
if grep -q "bcrypt" app/security.py 2>/dev/null; then
    ok "Password hashing: bcrypt in use"
else
    warn "bcrypt not detected in app/security.py – verify password hash algorithm"
fi

# Security event logging
if grep -rn --include="*.py" "security_event_logger\|log_security_event" app/ 2>/dev/null | grep -qv '#'; then
    ok "Security event logging: security_event_logger calls found"
else
    warn "Security event logging not detected"
fi

# HSTS enforcement
if grep -q "Strict-Transport-Security" app/main.py 2>/dev/null; then
    ok "HSTS header set in SecurityHeadersMiddleware"
else
    fail "Strict-Transport-Security header not found in main.py"
fi

# OpenAPI docs auth-gated
if grep -q "docs_url=None" app/main.py 2>/dev/null; then
    ok "OpenAPI docs: auto-generated /docs disabled (auth-gated custom route)"
else
    warn "FastAPI auto docs may be enabled unauthenticated – check docs_url=None"
fi


# ── Summary ─────────────────────────────────────────────────────────────────────
echo
echo "======================================================================"
echo -e "${BOLD}Summary${NC}"
echo -e "  ${GREEN}Passed:${NC}   $PASS"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo -e "  ${RED}Failures:${NC} $FAIL"
echo "======================================================================"
echo
echo -e "${CYAN}  ℹ${NC} For live HTTP security tests, run:"
echo -e "  ${CYAN}    python doc/security/test_security_features.py --url http://localhost:8000 --password <admin-pw>${NC}"
echo

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Security check FAILED – address failures before deployment.${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "${YELLOW}Security check passed with warnings – review before production.${NC}"
    exit 0
else
    echo -e "${GREEN}All security checks passed.${NC}"
    exit 0
fi
