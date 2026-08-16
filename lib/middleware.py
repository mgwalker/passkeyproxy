from aiohttp import web

from lib.credential_store import cred_store
from lib.logger import logger
from lib.util import get_client_ip, get_target_host, verify_jwt


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Authentication middleware"""
    # Skip auth for setup and API endpoints
    if request.path in [
        "/ppauth/setup",
        "/ppauth/login",
        "/ppauth/register",
    ] or request.path.startswith("/ppauth/api/"):
        return await handler(request)

    # Check for valid JWT
    token = request.cookies.get("session")

    target = get_target_host(request)
    auth_required = not target or target.get("AUTH_REQUIRED", True)

    if not token and auth_required:
        client_ip = get_client_ip(request)
        logger.warning(
            f"Missing session token from {client_ip} attempting {request.path}"
        )
        return web.HTTPFound("/ppauth/login")

    payload = verify_jwt(token)
    if not payload and auth_required:
        # Clear invalid cookie
        client_ip = get_client_ip(request)
        logger.warning(
            f"Invalid/expired session token from {client_ip} attempting {request.path}"
        )
        response = web.HTTPFound("/ppauth/login")
        response.del_cookie("session")
        return response

    # Store username in request
    if payload:
        request["authenticated_user"] = payload["username"]

    return await handler(request)


@web.middleware
async def setup_redirect_middleware(request: web.Request, handler):
    """Redirect to setup if no credentials exist"""
    if cred_store.is_empty() and request.path not in [
        "/ppauth/setup",
        "/ppauth/api/register/begin",
        "/ppauth/api/register/complete",
    ]:
        return web.HTTPFound("/ppauth/setup")

    return await handler(request)
