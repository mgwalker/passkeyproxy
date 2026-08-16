import urllib
from datetime import datetime, timedelta

import jwt
from aiohttp import web

from lib.config import CONFIG


def format_credential_id(cred_id: str) -> str:
    """Format credential ID for logging (first 8 chars only)"""
    return cred_id[:8] if cred_id else "unknown"


def get_client_ip(request: web.Request) -> str:
    """Get client IP address, respecting X-Forwarded-For header"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can be a list; take the first (original client)
        return forwarded_for.split(",")[0].strip()
    return request.remote or "unknown"


def get_origin(request: web.Request) -> str:
    """Get origin URL"""
    host = request.headers.get("Host", "localhost")
    scheme = request.headers.get("X-Forwarded-Proto", "http")
    return f"{scheme}://{host}"


def get_rp_id(request: web.Request) -> str:
    """Extract RP ID from Host header"""
    host = request.headers.get("Host", "localhost")
    # Remove port if present
    return host.split(":")[0]


def create_jwt(username: str, expiry_hours: int | None = None) -> str:
    """Create JWT token for authenticated session"""
    hours = expiry_hours if expiry_hours is not None else CONFIG["SESSION_EXPIRY_HOURS"]
    expiry = datetime.utcnow() + timedelta(hours=hours)
    payload = {"username": username, "exp": expiry, "iat": datetime.utcnow()}
    return jwt.encode(payload, CONFIG["JWT_SECRET_KEY"], algorithm="HS256")


def verify_jwt(token: str) -> dict | None:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, CONFIG["JWT_SECRET_KEY"], algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_target_host(request: web.Request) -> str:
    origin = urllib.parse.urlsplit(get_origin(request)).hostname

    match = CONFIG["TARGET_HOST"].get(origin.lower())
    if match:
        return match

    # There's no match, so use the catchall, if present
    return CONFIG["TARGET_HOST"].get("*")
