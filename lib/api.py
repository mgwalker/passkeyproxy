import json
import secrets
import time

from aiohttp import web
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from lib.challenges import (
    get_challenge,
    remove_challenge,
    set_challenge,
    validate_challenge,
)
from lib.config import CONFIG
from lib.credential_store import cred_store
from lib.csrf_tokens import (
    validate_csrf_token,
)
from lib.logger import logger
from lib.rate_limit import rate_limit
from lib.util import (
    create_jwt,
    format_credential_id,
    get_client_ip,
    get_origin,
    get_rp_id,
)

RATE_LIMIT_BEGIN_ENDPOINTS = 10  # requests per minute
RATE_LIMIT_COMPLETE_ENDPOINTS = 20  # requests per minute


@rate_limit(RATE_LIMIT_BEGIN_ENDPOINTS)
async def handle_register_begin(request: web.Request) -> web.Response:
    """Begin WebAuthn registration"""
    try:
        # Validate CSRF token
        csrf_token_id = request.headers.get("X-CSRF-Token-ID")
        csrf_token_value = request.headers.get("X-CSRF-Token-Value")
        if not validate_csrf_token(csrf_token_id, csrf_token_value):
            client_ip = get_client_ip(request)
            reason = (
                "missing"
                if not csrf_token_id or not csrf_token_value
                else "invalid/expired"
            )
            logger.warning(
                f"CSRF token validation failed from {client_ip} for /ppauth/api/register/begin (reason: {reason})"  # noqa: E501
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        data = await request.json()
        username = data.get("username", "").strip()

        if not username:
            return web.Response(text="Username required", status=400)

        rp_id = get_rp_id(request)

        # Generate registration options
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=CONFIG["RP_NAME"],
            user_id=secrets.token_bytes(32),
            user_name=username,
            user_display_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )

        # Store challenge
        challenge_id = secrets.token_urlsafe(32)
        set_challenge(
            challenge_id,
            {
                "challenge": options.challenge,
                "username": username,
                "timestamp": time.time(),
                "type": "registration",
            },
        )

        # Convert to dict and add challenge_id
        options_dict = json.loads(options_to_json(options))
        options_dict["challenge_id"] = challenge_id

        return web.json_response(options_dict)

    except Exception as e:
        logger.error(f"Registration begin error: {e}")
        return web.Response(text="Registration failed", status=500)


@rate_limit(RATE_LIMIT_COMPLETE_ENDPOINTS)
async def handle_register_complete(request: web.Request) -> web.Response:
    """Complete WebAuthn registration"""
    username = "unknown"
    client_ip = "unknown"
    try:
        # Extract client IP early for exception handler
        client_ip = get_client_ip(request)

        # Validate CSRF token
        csrf_token_id = request.headers.get("X-CSRF-Token-ID")
        csrf_token_value = request.headers.get("X-CSRF-Token-Value")
        if not validate_csrf_token(csrf_token_id, csrf_token_value):
            reason = (
                "missing"
                if not csrf_token_id or not csrf_token_value
                else "invalid/expired"
            )
            logger.warning(
                f"CSRF token validation failed from {client_ip} for /ppauth/api/register/complete (reason: {reason})"  # noqa: E501
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        data = await request.json()
        credential = data.get("credential")
        username = data.get("username")
        challenge_id = data.get("challenge_id")

        if not credential or not username:
            return web.Response(text="Invalid request", status=400)

        if not challenge_id:
            return web.Response(text="Challenge ID required", status=400)

        # Look up challenge by ID
        challenge_data = get_challenge(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for registration")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge(challenge_id):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired registration challenge from {client_ip} (age: {age}s)"
            )
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's a registration challenge for the right user
        if (
            challenge_data.get("type") != "registration"
            or challenge_data.get("username") != username
        ):
            client_ip = get_client_ip(request)
            if challenge_data.get("type") != "registration":
                logger.warning(
                    f"Challenge type mismatch from {client_ip} (expected: registration, got: {challenge_data.get('type')})"  # noqa: E501
                )
            else:
                logger.warning(
                    f"Challenge username mismatch from {client_ip} for registration"
                )
            remove_challenge(challenge_id)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        remove_challenge(challenge_id)

        rp_id = get_rp_id(request)
        origin = get_origin(request)

        # Verify registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge_data["challenge"],
            expected_rp_id=rp_id,
            expected_origin=origin,
        )

        # Store credential
        cred_store.add_credential(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            username=username,
            sign_count=verification.sign_count,
            credential_data=credential,
        )

        # Log successful registration
        client_ip = get_client_ip(request)
        cred_id_short = format_credential_id(
            bytes_to_base64url(verification.credential_id)
        )
        # Check if this is initial setup or new user registration
        if len(cred_store.credentials) == 1:
            logger.info(
                f"Initial admin '{username}' registered from {client_ip} (credential: {cred_id_short})"  # noqa: E501
            )
        else:
            logger.info(
                f"User '{username}' registered from {client_ip} (credential: {cred_id_short})"  # noqa: E501
            )

        return web.Response(text="Registration successful", status=200)

    except Exception as e:
        logger.warning(
            f"Registration failed for user '{username}' from {client_ip}: {e!s}"
        )
        return web.Response(text="Registration failed", status=500)


@rate_limit(RATE_LIMIT_BEGIN_ENDPOINTS)
async def handle_login_begin(request: web.Request) -> web.Response:
    """Begin WebAuthn authentication"""
    try:
        # Validate CSRF token
        csrf_token_id = request.headers.get("X-CSRF-Token-ID")
        csrf_token_value = request.headers.get("X-CSRF-Token-Value")
        if not validate_csrf_token(csrf_token_id, csrf_token_value):
            client_ip = get_client_ip(request)
            reason = (
                "missing"
                if not csrf_token_id or not csrf_token_value
                else "invalid/expired"
            )
            logger.warning(
                f"CSRF token validation failed from {client_ip} for /ppauth/api/login/begin (reason: {reason})"  # noqa: E501
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        if cred_store.is_empty():
            return web.Response(text="No credentials registered", status=400)

        rp_id = get_rp_id(request)

        # Get all credentials
        credentials = cred_store.get_all_credentials()
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred["id"]))
            for cred in credentials
        ]

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        # Store challenge
        challenge_id = secrets.token_urlsafe(32)
        set_challenge(
            challenge_id,
            {
                "challenge": options.challenge,
                "timestamp": time.time(),
                "type": "authentication",
            },
        )

        # Convert to dict
        options_dict = json.loads(options_to_json(options))
        options_dict["challenge_id"] = challenge_id

        return web.json_response(options_dict)

    except Exception as e:
        logger.error(f"Login begin error: {e}")
        return web.Response(text="Authentication failed", status=500)


@rate_limit(RATE_LIMIT_COMPLETE_ENDPOINTS)
async def handle_login_complete(request: web.Request) -> web.Response:
    """Complete WebAuthn authentication"""
    cred_id_short = "unknown"
    client_ip = "unknown"
    try:
        # Extract client IP early for exception handler
        client_ip = get_client_ip(request)

        # Validate CSRF token
        csrf_token_id = request.headers.get("X-CSRF-Token-ID")
        csrf_token_value = request.headers.get("X-CSRF-Token-Value")
        if not validate_csrf_token(csrf_token_id, csrf_token_value):
            reason = (
                "missing"
                if not csrf_token_id or not csrf_token_value
                else "invalid/expired"
            )
            logger.warning(
                f"CSRF token validation failed from {client_ip} for /ppauth/api/login/complete (reason: {reason})"  # noqa: E501
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        data = await request.json()
        credential = data.get("credential")
        challenge_id = data.get("challenge_id")
        remember_me = data.get("remember_me", False)

        if not credential:
            return web.Response(text="Invalid request", status=400)

        if not challenge_id:
            return web.Response(text="Challenge ID required", status=400)

        # Find credential in store
        cred_id = base64url_to_bytes(credential["rawId"])
        cred_id_short = format_credential_id(credential["rawId"])
        stored_cred = cred_store.get_credential_by_id(cred_id)

        if not stored_cred:
            return web.Response(text="Credential not found", status=400)

        # Look up challenge by ID
        challenge_data = get_challenge(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for authentication")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge(challenge_id):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired authentication challenge from {client_ip} (age: {age}s)"
            )
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's an authentication challenge
        if challenge_data.get("type") != "authentication":
            client_ip = get_client_ip(request)
            logger.warning(
                f"Challenge type mismatch from {client_ip} (expected: authentication, got: {challenge_data.get('type')})"  # noqa: E501
            )
            remove_challenge(challenge_id)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        remove_challenge(challenge_id)

        rp_id = get_rp_id(request)
        origin = get_origin(request)

        # Verify authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_data["challenge"],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
            credential_current_sign_count=stored_cred["sign_count"],
        )

        # Update sign count
        cred_store.update_sign_count(cred_id, verification.new_sign_count)

        # Determine session expiry hours
        expiry_hours = 24 if remember_me else CONFIG["SESSION_EXPIRY_HOURS"]

        # Log successful authentication
        client_ip = get_client_ip(request)
        cred_id_short = format_credential_id(stored_cred["id"])
        logger.info(
            f"User '{stored_cred['username']}' authenticated from {client_ip} (credential: {cred_id_short}, remember_me={remember_me}, {expiry_hours}h session)"  # noqa: E501
        )

        # Create JWT
        token = create_jwt(stored_cred["username"], expiry_hours=expiry_hours)

        # Set cookie
        response = web.Response(text="Authentication successful", status=200)
        response.set_cookie(
            "session",
            token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=expiry_hours * 3600,
        )

        return response

    except Exception as e:
        logger.warning(
            f"Authentication failed from {client_ip} (credential: {cred_id_short}): {e!s}"  # noqa: E501
        )
        return web.Response(text="Authentication failed", status=500)


@rate_limit(RATE_LIMIT_BEGIN_ENDPOINTS)
async def handle_register_auth_begin(request: web.Request) -> web.Response:
    """Begin authentication for registration (same as login)"""
    return await handle_login_begin(request)


@rate_limit(RATE_LIMIT_COMPLETE_ENDPOINTS)
async def handle_register_auth_complete(request: web.Request) -> web.Response:
    """Complete authentication for registration (no cookie needed)"""
    try:
        # Validate CSRF token
        csrf_token_id = request.headers.get("X-CSRF-Token-ID")
        csrf_token_value = request.headers.get("X-CSRF-Token-Value")
        if not validate_csrf_token(csrf_token_id, csrf_token_value):
            client_ip = get_client_ip(request)
            reason = (
                "missing"
                if not csrf_token_id or not csrf_token_value
                else "invalid/expired"
            )
            logger.warning(
                f"CSRF token validation failed from {client_ip} for /ppauth/api/register-auth/complete (reason: {reason})"  # noqa: E501
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        data = await request.json()
        credential = data.get("credential")
        challenge_id = data.get("challenge_id")

        if not credential:
            return web.Response(text="Invalid request", status=400)

        if not challenge_id:
            return web.Response(text="Challenge ID required", status=400)

        cred_id = base64url_to_bytes(credential["rawId"])
        stored_cred = cred_store.get_credential_by_id(cred_id)

        if not stored_cred:
            return web.Response(text="Credential not found", status=400)

        # Look up challenge by ID
        challenge_data = get_challenge(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for authentication")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge(challenge_id):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired authentication challenge from {client_ip} (age: {age}s)"
            )
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's an authentication challenge
        if challenge_data.get("type") != "authentication":
            client_ip = get_client_ip(request)
            logger.warning(
                f"Challenge type mismatch from {client_ip} (expected: authentication, got: {challenge_data.get('type')})"  # noqa: E501
            )
            remove_challenge(challenge_id)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        remove_challenge(challenge_id)

        rp_id = get_rp_id(request)
        origin = get_origin(request)

        # Verify authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_data["challenge"],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
            credential_current_sign_count=stored_cred["sign_count"],
        )

        cred_store.update_sign_count(cred_id, verification.new_sign_count)

        # Return success without setting cookie
        return web.Response(text="Authentication successful", status=200)

    except Exception as e:
        logger.error(f"Register auth complete error: {e}")
        return web.Response(text="Authentication failed", status=500)
