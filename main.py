#!/usr/bin/env python3
"""
Passkey-authenticated HTTP Reverse Proxy
Single-file implementation for home/hobby use
"""

from aiohttp import web

import lib.middleware
import lib.pages as pages
from lib.api import (
    handle_login_begin,
    handle_login_complete,
    handle_register_auth_begin,
    handle_register_auth_complete,
    handle_register_begin,
    handle_register_complete,
)
from lib.cleanup import cleanup_background_task
from lib.config import CONFIG
from lib.credential_store import cred_store
from lib.csrf_tokens import (
    generate_csrf_token,
)
from lib.logger import logger
from lib.proxy import handle_proxy
from lib.rate_limit import rate_limit
from lib.util import get_origin

# Security constants
CLEANUP_INTERVAL_SECONDS = 30  # Run cleanup every 30 seconds

# Rate limiting constants (per IP, per endpoint)
RATE_LIMIT_BEGIN_ENDPOINTS = 10  # requests per minute
RATE_LIMIT_COMPLETE_ENDPOINTS = 20  # requests per minute
RATE_LIMIT_PAGE_ENDPOINTS = 30  # requests per minute
RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window


# Route Handlers
@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_setup(request: web.Request) -> web.Response:
    """Show setup page if no credentials exist"""
    origin = get_origin(request)
    if not cred_store.is_empty_for_host(host=origin):
        return web.HTTPFound("/ppauth/login")
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=pages.setup_page(csrf_token_id, csrf_token_value), content_type="text/html"
    )


@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_login(request: web.Request) -> web.Response:
    """Show login page"""
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=pages.login_page(csrf_token_id, csrf_token_value), content_type="text/html"
    )


@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_register_page(request: web.Request) -> web.Response:
    """Show registration page"""
    origin = get_origin(request)
    if cred_store.is_empty_for_host(host=origin):
        return web.HTTPFound("/ppauth/setup")
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=pages.register_page(csrf_token_id, csrf_token_value),
        content_type="text/html",
    )


# Application setup


def create_app() -> web.Application:
    """Create and configure the application"""
    app = web.Application(
        middlewares=[
            lib.middleware.setup_redirect_middleware,
            lib.middleware.auth_middleware,
        ]
    )

    # Register background cleanup task
    app.cleanup_ctx.append(cleanup_background_task)

    # Add routes
    app.router.add_get("/ppauth/setup", handle_setup)
    app.router.add_get("/ppauth/login", handle_login)
    app.router.add_get("/ppauth/register", handle_register_page)

    # API routes
    app.router.add_post("/ppauth/api/register/begin", handle_register_begin)
    app.router.add_post("/ppauth/api/register/complete", handle_register_complete)
    app.router.add_post("/ppauth/api/login/begin", handle_login_begin)
    app.router.add_post("/ppauth/api/login/complete", handle_login_complete)
    app.router.add_post("/ppauth/api/register-auth/begin", handle_register_auth_begin)
    app.router.add_post(
        "/ppauth/api/register-auth/complete", handle_register_auth_complete
    )

    # Proxy all other requests
    app.router.add_route("*", "/{path:.*}", handle_proxy)

    return app


def main():
    """Main entry point"""
    # Validate JWT secret key
    if not CONFIG["JWT_SECRET_KEY"]:
        print("\nERROR: JWT_SECRET_KEY must be explicitly set in .env file")
        print(
            "Generate a secure key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"  # noqa: E501
        )
        print("Then add to .env: JWT_SECRET_KEY=<generated_key>")
        return

    # Validate key is strong enough (at least 32 bytes when base64url decoded)
    if len(CONFIG["JWT_SECRET_KEY"]) < 43:  # 32 bytes base64url encoded is ~43 chars
        logger.warning("JWT_SECRET_KEY is shorter than recommended 32 bytes (256 bits)")
        print(
            "Generate a new key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"  # noqa: E501
        )

    # Validate required config
    if not CONFIG["TARGET_HOST"]:
        logger.error("TARGET_HOST must be set")
        return

    logger.info(
        f"Passkey Proxy starting on {CONFIG['PROXY_LISTEN_HOST']}:{CONFIG['PROXY_LISTEN_PORT']}, proxying to :"  # noqa: E501
    )

    for host, target in CONFIG["TARGET_HOST"].items():
        logger.info(f"  - {host} -> {target['TARGET']}")

    logger.info(f"Session expiry: {CONFIG['SESSION_EXPIRY_HOURS']} hours")

    logger.info(
        f"Loaded {len(cred_store.credentials)} registered user(s) from {CONFIG['CREDENTIALS_FILE']}"  # noqa: E501
    )

    app = create_app()
    web.run_app(
        app,
        host=CONFIG["PROXY_LISTEN_HOST"],
        port=CONFIG["PROXY_LISTEN_PORT"],
        print=None,  # Suppress aiohttp startup messages
    )


if __name__ == "__main__":
    main()
