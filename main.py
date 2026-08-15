#!/usr/bin/env python3
"""
Passkey-authenticated HTTP Reverse Proxy
Single-file implementation for home/hobby use
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib
from datetime import datetime, timedelta
from pathlib import Path

import jwt
from aiohttp import ClientSession, ClientTimeout, web
from dotenv import load_dotenv
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

load_dotenv()

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load configuration from environment variables
CONFIG = {
    "PROXY_LISTEN_HOST": os.getenv("PROXY_LISTEN_HOST", "0.0.0.0"),
    "PROXY_LISTEN_PORT": int(os.getenv("PROXY_LISTEN_PORT", "8080")),
    "TARGET_HOST": os.getenv("TARGET_HOST", "localhost"),
    "TARGET_PORT": int(os.getenv("TARGET_PORT", "3000")),
    "SESSION_EXPIRY_HOURS": int(os.getenv("SESSION_EXPIRY_HOURS", "24")),
    "JWT_SECRET_KEY": os.getenv(
        "JWT_SECRET_KEY"
    ),  # No fallback - must be explicitly set
    "RP_NAME": os.getenv("RP_NAME", "Passkey Proxy"),
    "CREDENTIALS_FILE": os.getenv("CREDENTIALS_FILE", "./credentials.json"),
}

try:
    hosts = json.loads(CONFIG["TARGET_HOST"])
    CONFIG["TARGET_HOST"] = None
    CONFIG["TARGET_HOSTS"] = {host.lower(): target for host, target in hosts.items()}
except:
    pass

# Security constants
CHALLENGE_EXPIRY_SECONDS = 60  # WebAuthn challenges expire after 60 seconds
CSRF_TOKEN_EXPIRY_SECONDS = 600  # CSRF tokens expire after 10 minutes
MAX_CHALLENGES = 1000  # Maximum number of challenges in memory
MAX_CSRF_TOKENS = 1000  # Maximum number of CSRF tokens in memory
CLEANUP_INTERVAL_SECONDS = 30  # Run cleanup every 30 seconds

# Rate limiting constants (per IP, per endpoint)
RATE_LIMIT_BEGIN_ENDPOINTS = 10  # requests per minute
RATE_LIMIT_COMPLETE_ENDPOINTS = 20  # requests per minute
RATE_LIMIT_PAGE_ENDPOINTS = 30  # requests per minute
RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window

# In-memory storage
CHALLENGES: dict[
    str, dict
] = {}  # challenge_id -> {challenge, username, timestamp, type}
CSRF_TOKENS: dict[str, float] = {}  # csrf_token_id -> timestamp
RATE_LIMITS: dict[
    str, dict[str, dict]
] = {}  # ip -> {endpoint -> {count, window_start}}


class CredentialStore:
    """Manages credential storage in JSON file"""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.credentials: list[dict] = []
        self._load()

    def _load(self):
        """Load credentials from file"""
        if self.filepath.exists():
            try:
                with open(self.filepath, "r") as f:
                    data = json.load(f)
                    self.credentials = data.get("credentials", [])
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
                self.credentials = []
        else:
            self.credentials = []

    def _save(self):
        """Save credentials to file"""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w") as f:
                json.dump({"credentials": self.credentials}, f, indent=2)
            os.chmod(self.filepath, 0o600)
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")

    def is_empty(self) -> bool:
        """Check if there are no credentials"""
        return len(self.credentials) == 0

    def add_credential(
        self,
        credential_id: bytes,
        public_key: bytes,
        username: str,
        sign_count: int,
        credential_data: dict,
    ):
        """Add a new credential"""
        cred_id_b64 = bytes_to_base64url(credential_id)
        self.credentials.append(
            {
                "id": cred_id_b64,
                "public_key": bytes_to_base64url(public_key),
                "sign_count": sign_count,
                "username": username,
                "credential_data": credential_data,
                "created_at": datetime.utcnow().isoformat(),
            }
        )
        self._save()
        logger.info(
            f"Credential stored for user '{username}' (credential: {format_credential_id(cred_id_b64)})"
        )

    def get_all_credentials(self) -> list[dict]:
        """Get all credentials for authentication"""
        return self.credentials

    def get_credential_by_id(self, credential_id: bytes) -> dict | None:
        """Find credential by ID"""
        cred_id_b64 = bytes_to_base64url(credential_id)
        for cred in self.credentials:
            if cred["id"] == cred_id_b64:
                return cred
        return None

    def update_sign_count(self, credential_id: bytes, sign_count: int):
        """Update sign count for a credential"""
        cred = self.get_credential_by_id(credential_id)
        if cred:
            old_count = cred["sign_count"]
            cred["sign_count"] = sign_count
            self._save()
            logger.info(
                f"Sign count updated for user '{cred['username']}' (credential: {format_credential_id(cred['id'])}, count: {sign_count})"
            )

            # Check for sign count anomaly (possible credential cloning)
            # Only check if both old and new counts are non-zero (authenticator supports sign count)
            # Per WebAuthn spec, sign_count=0 means "not supported"
            if old_count > 0 and sign_count > 0 and sign_count <= old_count:
                logger.warning(
                    f"Sign count anomaly for user '{cred['username']}' (expected > {old_count}, got {sign_count}) - possible credential cloning"
                )


# Initialize credential store
cred_store = CredentialStore(CONFIG["CREDENTIALS_FILE"])


# Security helper functions


def generate_csrf_token() -> tuple[str, str]:
    """Generate CSRF token with HMAC signature"""
    token_id = secrets.token_urlsafe(32)
    timestamp = time.time()

    # Compute HMAC signature over token_id + timestamp
    message = f"{token_id}:{timestamp}".encode()
    token_value = hmac.new(
        CONFIG["JWT_SECRET_KEY"].encode("utf-8"), message, hashlib.sha256
    ).hexdigest()

    CSRF_TOKENS[token_id] = timestamp
    return (token_id, token_value)


def validate_csrf_token(token_id: str, token_value: str) -> bool:
    """Validate CSRF token with HMAC verification (reusable per page session)"""
    if not token_id or not token_value:
        return False

    # Check if token exists
    timestamp = CSRF_TOKENS.get(token_id)
    if timestamp is None:
        return False

    # Check if token is expired
    if time.time() - timestamp > CSRF_TOKEN_EXPIRY_SECONDS:
        CSRF_TOKENS.pop(token_id, None)
        return False

    # Recompute HMAC and verify
    message = f"{token_id}:{timestamp}".encode()
    expected_value = hmac.new(
        CONFIG["JWT_SECRET_KEY"].encode("utf-8"), message, hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(token_value, expected_value)


def validate_challenge_timestamp(
    timestamp: float, max_age: int = CHALLENGE_EXPIRY_SECONDS
) -> bool:
    """Validate that a challenge timestamp is not expired"""
    return (time.time() - timestamp) <= max_age


def get_client_ip(request: web.Request) -> str:
    """Get client IP address, respecting X-Forwarded-For header"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can be a list; take the first (original client)
        return forwarded_for.split(",")[0].strip()
    return request.remote or "unknown"


def format_credential_id(cred_id: str) -> str:
    """Format credential ID for logging (first 8 chars only)"""
    return cred_id[:8] if cred_id else "unknown"


def cleanup_expired_items():
    """Remove expired challenges, CSRF tokens, and rate limit entries"""
    current_time = time.time()

    # Cleanup expired challenges
    expired_challenges = [
        cid
        for cid, data in CHALLENGES.items()
        if current_time - data.get("timestamp", 0) > CHALLENGE_EXPIRY_SECONDS
    ]
    for cid in expired_challenges:
        CHALLENGES.pop(cid, None)

    # Cleanup expired CSRF tokens
    expired_csrf = [
        tid
        for tid, timestamp in CSRF_TOKENS.items()
        if current_time - timestamp > CSRF_TOKEN_EXPIRY_SECONDS
    ]
    for tid in expired_csrf:
        CSRF_TOKENS.pop(tid, None)

    # Track cleanup for DEBUG logging
    challenges_pruned = 0
    csrf_pruned = 0

    # Enforce max limits (remove oldest if over limit)
    if len(CHALLENGES) > MAX_CHALLENGES:
        before = len(CHALLENGES)
        # Sort by timestamp and keep only the newest MAX_CHALLENGES
        sorted_challenges = sorted(
            CHALLENGES.items(), key=lambda x: x[1].get("timestamp", 0), reverse=True
        )
        CHALLENGES.clear()
        CHALLENGES.update(dict(sorted_challenges[:MAX_CHALLENGES]))
        challenges_pruned = before - len(CHALLENGES)
        logger.warning(
            f"Challenge storage limit reached, pruned {challenges_pruned} expired entries"
        )

    if len(CSRF_TOKENS) > MAX_CSRF_TOKENS:
        before = len(CSRF_TOKENS)
        # Sort by timestamp and keep only the newest MAX_CSRF_TOKENS
        sorted_csrf = sorted(CSRF_TOKENS.items(), key=lambda x: x[1], reverse=True)
        CSRF_TOKENS.clear()
        CSRF_TOKENS.update(dict(sorted_csrf[:MAX_CSRF_TOKENS]))
        csrf_pruned = before - len(CSRF_TOKENS)
        logger.warning(
            f"CSRF token storage limit reached, pruned {csrf_pruned} expired entries"
        )

    # Cleanup old rate limit entries
    rate_limits_cleaned = 0
    for ip in list(RATE_LIMITS.keys()):
        for endpoint in list(RATE_LIMITS[ip].keys()):
            window_start = RATE_LIMITS[ip][endpoint].get("window_start", 0)
            if current_time - window_start > RATE_LIMIT_WINDOW_SECONDS * 2:
                RATE_LIMITS[ip].pop(endpoint, None)
                rate_limits_cleaned += 1
        # Remove IP if no endpoints remain
        if not RATE_LIMITS[ip]:
            RATE_LIMITS.pop(ip, None)

    # DEBUG logging for regular cleanup (only if something was cleaned)
    total_cleaned = len(expired_challenges) + len(expired_csrf) + rate_limits_cleaned
    if total_cleaned > 0:
        logger.debug(
            f"Cleanup: removed {len(expired_challenges)} challenges, {len(expired_csrf)} CSRF tokens, {rate_limits_cleaned} rate limit entries"
        )


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


def get_rp_id(request: web.Request) -> str:
    """Extract RP ID from Host header"""
    host = request.headers.get("Host", "localhost")
    # Remove port if present
    return host.split(":")[0]


def get_origin(request: web.Request) -> str:
    """Get origin URL"""
    host = request.headers.get("Host", "localhost")
    scheme = request.headers.get("X-Forwarded-Proto", "http")
    return f"{scheme}://{host}"


# Rate limiting decorator


def rate_limit(max_requests: int, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
    """
    Rate limiting decorator for route handlers
    Limits requests per IP address per endpoint
    """

    def decorator(handler):
        async def wrapper(request: web.Request) -> web.Response:
            client_ip = get_client_ip(request)
            endpoint = request.path
            current_time = time.time()

            # Initialize rate limit tracking for this IP
            if client_ip not in RATE_LIMITS:
                RATE_LIMITS[client_ip] = {}

            # Initialize tracking for this endpoint
            if endpoint not in RATE_LIMITS[client_ip]:
                RATE_LIMITS[client_ip][endpoint] = {
                    "count": 0,
                    "window_start": current_time,
                }

            endpoint_data = RATE_LIMITS[client_ip][endpoint]

            # Check if we're in a new window
            if current_time - endpoint_data["window_start"] > window_seconds:
                # Reset window
                endpoint_data["count"] = 0
                endpoint_data["window_start"] = current_time

            # Check rate limit
            if endpoint_data["count"] >= max_requests:
                # Rate limit exceeded
                retry_after = (
                    int(window_seconds - (current_time - endpoint_data["window_start"]))
                    + 1
                )
                logger.warning(
                    f"Rate limit exceeded from {client_ip} for {endpoint} (retry after {retry_after}s)"
                )
                response = web.Response(
                    text="Too many requests. Please try again later.", status=429
                )
                response.headers["Retry-After"] = str(retry_after)
                return response

            # Increment counter
            endpoint_data["count"] += 1

            # Call the actual handler
            return await handler(request)

        return wrapper

    return decorator


# HTML Templates
DARK_STYLE = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
        background: #1a1a1a;
        color: #e0e0e0;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        padding: 20px;
    }
    .container {
        max-width: 400px;
        width: 100%;
        text-align: center;
    }
    h1 {
        font-size: 24px;
        margin-bottom: 10px;
        color: #ffffff;
    }
    p {
        margin-bottom: 30px;
        color: #b0b0b0;
        font-size: 14px;
    }
    input[type="text"] {
        width: 100%;
        padding: 12px;
        margin-bottom: 20px;
        background: #2a2a2a;
        border: 1px solid #3a3a3a;
        border-radius: 6px;
        color: #e0e0e0;
        font-size: 14px;
    }
    input[type="text"]:focus {
        outline: none;
        border-color: #4a9eff;
    }
    button {
        width: 100%;
        padding: 14px;
        background: #4a9eff;
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
    }
    button:hover {
        background: #3a8eef;
    }
    button:active {
        background: #2a7edf;
    }
    .link {
        display: inline-block;
        margin-top: 20px;
        color: #4a9eff;
        text-decoration: none;
        font-size: 13px;
    }
    .link:hover {
        text-decoration: underline;
    }
    .error {
        background: #ff4444;
        color: white;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 20px;
        font-size: 14px;
    }
    .status {
        margin-top: 20px;
        font-size: 13px;
        color: #b0b0b0;
    }
    .remember-me {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 20px;
        gap: 8px;
    }
    .remember-me input[type="checkbox"] {
        width: 16px;
        height: 16px;
        cursor: pointer;
        accent-color: #4a9eff;
    }
    .remember-me label {
        font-size: 14px;
        color: #e0e0e0;
        cursor: pointer;
        user-select: none;
    }
</style>
"""


def setup_page(csrf_token_id: str, csrf_token_value: str) -> str:
    """Initial setup page HTML"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Initial Setup - {CONFIG["RP_NAME"]}</title>
    {DARK_STYLE}
</head>
<body>
    <div class="container">
        <h1>Initial Setup</h1>
        <p>Register the first admin user with a passkey</p>
        <div id="error" class="error" style="display:none;"></div>
        <input type="text" id="username" placeholder="Username" required>
        <button onclick="register()">Register Admin Passkey</button>
        <div id="status" class="status"></div>
    </div>
    <script>
        async function register() {{
            const username = document.getElementById('username').value.trim();
            if (!username) {{
                showError('Please enter a username');
                return;
            }}
            
            document.getElementById('status').textContent = 'Starting registration...';
            
            try {{
                // Begin registration
                const beginResp = await fetch('/api/register/begin', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{username}})
                }});

                if (!beginResp.ok) {{
                    const error = await beginResp.text();
                    throw new Error(error || 'Failed to begin registration');
                }}

                const options = await beginResp.json();
                const challengeId = options.challenge_id;
                document.getElementById('status').textContent = 'Please interact with your authenticator...';

                // Create credential
                const credential = await navigator.credentials.create({{
                    publicKey: {{
                        ...options,
                        challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        user: {{
                            ...options.user,
                            id: Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
                        }}
                    }}
                }});
                
                document.getElementById('status').textContent = 'Completing registration...';
                
                // Complete registration
                const completeResp = await fetch('/api/register/complete', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{
                        credential: {{
                            id: credential.id,
                            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                            response: {{
                                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
                            }},
                            type: credential.type
                        }},
                        username,
                        challenge_id: challengeId
                    }})
                }});

                if (!completeResp.ok) {{
                    const error = await completeResp.text();
                    throw new Error(error || 'Failed to complete registration');
                }}

                document.getElementById('status').textContent = 'Success! Redirecting...';
                setTimeout(() => window.location.href = '/plogin', 1000);
                
            }} catch (error) {{
                showError(error.message);
                document.getElementById('status').textContent = '';
            }}
        }}
        
        function showError(message) {{
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }}
    </script>
</body>
</html>
"""


def login_page(csrf_token_id: str, csrf_token_value: str) -> str:
    """Login page HTML"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign In - {CONFIG["RP_NAME"]}</title>
    {DARK_STYLE}
</head>
<body>
    <div class="container">
        <h1>Sign In</h1>
        <p>Authenticate with your passkey</p>
        <div id="error" class="error" style="display:none;"></div>
        <div class="remember-me">
            <input type="checkbox" id="remember-me" />
            <label for="remember-me">Remember me for 24 hours</label>
        </div>
        <button onclick="authenticate()">Sign in with Passkey</button>
        <a href="/pregister" class="link">Register New User</a>
        <div id="status" class="status"></div>
    </div>
    <script>
        async function authenticate() {{
            document.getElementById('status').textContent = 'Starting authentication...';
            
            try {{
                // Begin authentication
                const beginResp = await fetch('/api/login/begin', {{
                    method: 'POST',
                    headers: {{
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }}
                }});

                if (!beginResp.ok) {{
                    throw new Error('Failed to begin authentication');
                }}

                const options = await beginResp.json();
                const challengeId = options.challenge_id;
                document.getElementById('status').textContent = 'Please interact with your authenticator...';

                // Get credential
                const credential = await navigator.credentials.get({{
                    publicKey: {{
                        ...options,
                        challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        allowCredentials: options.allowCredentials.map(cred => ({{
                            ...cred,
                            id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
                        }}))
                    }}
                }});
                
                document.getElementById('status').textContent = 'Completing authentication...';
                
                // Complete authentication
                const rememberMe = document.getElementById('remember-me').checked;
                const completeResp = await fetch('/api/login/complete', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{
                        credential: {{
                            id: credential.id,
                            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                            response: {{
                                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                                userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                            }},
                            type: credential.type
                        }},
                        challenge_id: challengeId,
                        remember_me: rememberMe
                    }})
                }});

                if (!completeResp.ok) {{
                    throw new Error('Authentication failed');
                }}

                document.getElementById('status').textContent = 'Success! Redirecting...';
                window.location.href = '/';
                
            }} catch (error) {{
                showError(error.message);
                document.getElementById('status').textContent = '';
            }}
        }}
        
        function showError(message) {{
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }}
    </script>
</body>
</html>
"""


def register_page(csrf_token_id: str, csrf_token_value: str) -> str:
    """Registration page for new users"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Register New User - {CONFIG["RP_NAME"]}</title>
    {DARK_STYLE}
</head>
<body>
    <div class="container">
        <div id="auth-step">
            <h1>Register New User</h1>
            <p>First, authenticate with your existing passkey</p>
            <div id="error" class="error" style="display:none;"></div>
            <button onclick="authenticateForRegistration()">Authenticate</button>
            <a href="/plogin" class="link">Back to Login</a>
            <div id="status" class="status"></div>
        </div>
        
        <div id="register-step" style="display:none;">
            <h1>Register New User</h1>
            <p>Register a passkey for the new user</p>
            <div id="error2" class="error" style="display:none;"></div>
            <input type="text" id="username" placeholder="Username for new user" required>
            <button onclick="registerNewUser()">Register New Passkey</button>
            <div id="status2" class="status"></div>
        </div>
    </div>
    <script>
        async function authenticateForRegistration() {{
            document.getElementById('status').textContent = 'Starting authentication...';
            
            try {{
                const beginResp = await fetch('/api/register-auth/begin', {{
                    method: 'POST',
                    headers: {{
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }}
                }});

                if (!beginResp.ok) {{
                    throw new Error('Failed to begin authentication');
                }}

                const options = await beginResp.json();
                const challengeId = options.challenge_id;
                document.getElementById('status').textContent = 'Please interact with your authenticator...';

                const credential = await navigator.credentials.get({{
                    publicKey: {{
                        ...options,
                        challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        allowCredentials: options.allowCredentials.map(cred => ({{
                            ...cred,
                            id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
                        }}))
                    }}
                }});
                
                document.getElementById('status').textContent = 'Verifying...';
                
                const completeResp = await fetch('/api/register-auth/complete', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{
                        credential: {{
                            id: credential.id,
                            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                            response: {{
                                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                                userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                            }},
                            type: credential.type
                        }},
                        challenge_id: challengeId
                    }})
                }});

                if (!completeResp.ok) {{
                    throw new Error('Authentication failed');
                }}

                document.getElementById('auth-step').style.display = 'none';
                document.getElementById('register-step').style.display = 'block';
                
            }} catch (error) {{
                showError(error.message);
                document.getElementById('status').textContent = '';
            }}
        }}
        
        async function registerNewUser() {{
            const username = document.getElementById('username').value.trim();
            if (!username) {{
                showError2('Please enter a username');
                return;
            }}
            
            document.getElementById('status2').textContent = 'Starting registration...';
            
            try {{
                const beginResp = await fetch('/api/register/begin', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{username}})
                }});

                if (!beginResp.ok) {{
                    throw new Error('Failed to begin registration');
                }}

                const options = await beginResp.json();
                const challengeId = options.challenge_id;
                document.getElementById('status2').textContent = 'Please interact with your authenticator...';

                const credential = await navigator.credentials.create({{
                    publicKey: {{
                        ...options,
                        challenge: Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
                        user: {{
                            ...options.user,
                            id: Uint8Array.from(atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
                        }}
                    }}
                }});
                
                document.getElementById('status2').textContent = 'Completing registration...';
                
                const completeResp = await fetch('/api/register/complete', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                        'X-CSRF-Token-ID': '{csrf_token_id}',
                        'X-CSRF-Token-Value': '{csrf_token_value}'
                    }},
                    body: JSON.stringify({{
                        credential: {{
                            id: credential.id,
                            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                            response: {{
                                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                                attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)))
                            }},
                            type: credential.type
                        }},
                        username,
                        challenge_id: challengeId
                    }})
                }});

                if (!completeResp.ok) {{
                    throw new Error('Failed to complete registration');
                }}

                document.getElementById('status2').textContent = 'Success! Redirecting...';
                setTimeout(() => window.location.href = '/plogin', 1000);
                
            }} catch (error) {{
                showError2(error.message);
                document.getElementById('status2').textContent = '';
            }}
        }}
        
        function showError(message) {{
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }}
        
        function showError2(message) {{
            const errorDiv = document.getElementById('error2');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }}
    </script>
</body>
</html>
"""


# Route Handlers


@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_setup(request: web.Request) -> web.Response:
    """Show setup page if no credentials exist"""
    if not cred_store.is_empty():
        return web.HTTPFound("/plogin")
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=setup_page(csrf_token_id, csrf_token_value), content_type="text/html"
    )


@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_login(request: web.Request) -> web.Response:
    """Show login page"""
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=login_page(csrf_token_id, csrf_token_value), content_type="text/html"
    )


@rate_limit(RATE_LIMIT_PAGE_ENDPOINTS)
async def handle_register_page(request: web.Request) -> web.Response:
    """Show registration page"""
    if cred_store.is_empty():
        return web.HTTPFound("/psetup")
    csrf_token_id, csrf_token_value = generate_csrf_token()
    return web.Response(
        text=register_page(csrf_token_id, csrf_token_value), content_type="text/html"
    )


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
                f"CSRF token validation failed from {client_ip} for /api/register/begin (reason: {reason})"
            )
            return web.Response(text="Invalid or expired CSRF token", status=403)

        data = await request.json()
        username = data.get("username", "").strip()

        if not username:
            return web.Response(text="Username required", status=400)

        rp_id = get_rp_id(request)
        origin = get_origin(request)

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
        CHALLENGES[challenge_id] = {
            "challenge": options.challenge,
            "username": username,
            "timestamp": time.time(),
            "type": "registration",
        }

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
                f"CSRF token validation failed from {client_ip} for /api/register/complete (reason: {reason})"
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
        challenge_data = CHALLENGES.get(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for registration")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge_timestamp(challenge_data.get("timestamp", 0)):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired registration challenge from {client_ip} (age: {age}s)"
            )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's a registration challenge for the right user
        if (
            challenge_data.get("type") != "registration"
            or challenge_data.get("username") != username
        ):
            client_ip = get_client_ip(request)
            if challenge_data.get("type") != "registration":
                logger.warning(
                    f"Challenge type mismatch from {client_ip} (expected: registration, got: {challenge_data.get('type')})"
                )
            else:
                logger.warning(
                    f"Challenge username mismatch from {client_ip} for registration"
                )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        CHALLENGES.pop(challenge_id, None)

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
                f"Initial admin '{username}' registered from {client_ip} (credential: {cred_id_short})"
            )
        else:
            logger.info(
                f"User '{username}' registered from {client_ip} (credential: {cred_id_short})"
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
                f"CSRF token validation failed from {client_ip} for /api/login/begin (reason: {reason})"
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
        CHALLENGES[challenge_id] = {
            "challenge": options.challenge,
            "timestamp": time.time(),
            "type": "authentication",
        }

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
                f"CSRF token validation failed from {client_ip} for /api/login/complete (reason: {reason})"
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
        challenge_data = CHALLENGES.get(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for authentication")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge_timestamp(challenge_data.get("timestamp", 0)):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired authentication challenge from {client_ip} (age: {age}s)"
            )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's an authentication challenge
        if challenge_data.get("type") != "authentication":
            client_ip = get_client_ip(request)
            logger.warning(
                f"Challenge type mismatch from {client_ip} (expected: authentication, got: {challenge_data.get('type')})"
            )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        CHALLENGES.pop(challenge_id, None)

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
            f"User '{stored_cred['username']}' authenticated from {client_ip} (credential: {cred_id_short}, remember_me={remember_me}, {expiry_hours}h session)"
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
            samesite="Strict",  # Changed from 'Lax' to 'Strict' for better CSRF protection
            max_age=expiry_hours * 3600,
        )

        return response

    except Exception as e:
        logger.warning(
            f"Authentication failed from {client_ip} (credential: {cred_id_short}): {e!s}"
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
                f"CSRF token validation failed from {client_ip} for /api/register-auth/complete (reason: {reason})"
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
        challenge_data = CHALLENGES.get(challenge_id)

        if not challenge_data:
            client_ip = get_client_ip(request)
            logger.warning(f"Challenge not found from {client_ip} for authentication")
            return web.Response(text="Challenge not found or expired", status=400)

        # Validate challenge timestamp
        if not validate_challenge_timestamp(challenge_data.get("timestamp", 0)):
            client_ip = get_client_ip(request)
            age = int(time.time() - challenge_data.get("timestamp", 0))
            logger.warning(
                f"Expired authentication challenge from {client_ip} (age: {age}s)"
            )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Challenge has expired", status=400)

        # Verify it's an authentication challenge
        if challenge_data.get("type") != "authentication":
            client_ip = get_client_ip(request)
            logger.warning(
                f"Challenge type mismatch from {client_ip} (expected: authentication, got: {challenge_data.get('type')})"
            )
            CHALLENGES.pop(challenge_id, None)
            return web.Response(text="Invalid challenge", status=400)

        # Clean up challenge (single-use)
        CHALLENGES.pop(challenge_id, None)

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


async def handle_websocket_proxy(request: web.Request) -> web.WebSocketResponse:
    """Proxy WebSocket connections to target application"""
    # Get authenticated username
    username = request.get("authenticated_user", "unknown")
    client_ip = get_client_ip(request)
    start_time = time.time()

    # DEBUG logging for WebSocket connection opened
    logger.debug(f"WebSocket opened: {username} -> {request.path} from {client_ip}")

    # Accept WebSocket connection from client
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)

    target = ""
    origin = urllib.parse.urlsplit(get_origin(request)).hostname

    if CONFIG["TARGET_HOST"]:
        target = f"{CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}"
    elif CONFIG["TARGET_HOSTS"].get(origin, None):
        target = f"{CONFIG['TARGET_HOSTS'][origin]}"

    # Build target WebSocket URL
    target_ws_url = f"ws://{target}{request.path_qs}"

    # Prepare headers for backend connection
    headers = {
        "X-Forwarded-User": username,
        "X-Forwarded-For": request.remote or "unknown",
        "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto", "http"),
    }

    # Copy other headers that might be relevant
    for key, value in request.headers.items():
        if key.lower() not in [
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
        ]:
            headers[key] = value

    backend_ws = None
    try:
        # Connect to backend WebSocket
        timeout = ClientTimeout(total=60)
        async with ClientSession(timeout=timeout) as session:
            backend_ws = await session.ws_connect(target_ws_url, headers=headers)

            # Create tasks for bidirectional forwarding
            async def forward_client_to_backend():
                """Forward messages from client to backend"""
                try:
                    async for msg in client_ws:
                        if msg.type == web.WSMsgType.TEXT:
                            await backend_ws.send_str(msg.data)
                        elif msg.type == web.WSMsgType.BINARY:
                            await backend_ws.send_bytes(msg.data)
                        elif msg.type == web.WSMsgType.CLOSE:
                            await backend_ws.close()
                            break
                        elif msg.type == web.WSMsgType.ERROR:
                            logger.error(
                                f"WebSocket client error: {client_ws.exception()}"
                            )
                            break
                except Exception as e:
                    logger.error(f"Error forwarding client to backend: {e}")

            async def forward_backend_to_client():
                """Forward messages from backend to client"""
                try:
                    async for msg in backend_ws:
                        if msg.type == web.WSMsgType.TEXT:
                            await client_ws.send_str(msg.data)
                        elif msg.type == web.WSMsgType.BINARY:
                            await client_ws.send_bytes(msg.data)
                        elif msg.type == web.WSMsgType.CLOSE:
                            await client_ws.close()
                            break
                        elif msg.type == web.WSMsgType.ERROR:
                            logger.error(
                                f"WebSocket backend error: {backend_ws.exception()}"
                            )
                            break
                except Exception as e:
                    logger.error(f"Error forwarding backend to client: {e}")

            # Run both forwarding tasks concurrently
            await asyncio.gather(
                forward_client_to_backend(),
                forward_backend_to_client(),
                return_exceptions=True,
            )

    except Exception as e:
        logger.error(f"WebSocket proxy error: {e}")
    finally:
        # Cleanup connections
        if backend_ws and not backend_ws.closed:
            await backend_ws.close()
        if not client_ws.closed:
            await client_ws.close()

        # DEBUG logging for WebSocket connection closed
        duration = int(time.time() - start_time)
        logger.debug(
            f"WebSocket closed: {username} from {client_ip} (duration: {duration}s)"
        )

    return client_ws


async def handle_proxy(request: web.Request) -> web.Response:
    """Proxy requests to target application"""
    try:
        # Detect WebSocket upgrade requests
        if (
            request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in request.headers.get("Connection", "").lower()
        ):
            return await handle_websocket_proxy(request)

        target = ""
        origin = urllib.parse.urlsplit(get_origin(request)).hostname

        if CONFIG["TARGET_HOST"]:
            target = f"{CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}"
        elif CONFIG["TARGET_HOSTS"].get(origin, None):
            target = f"{CONFIG['TARGET_HOSTS'][origin]}"

        # Build target URL
        target_url = f"http://{target}{request.path_qs}"

        # Get authenticated username
        username = request.get("authenticated_user", "unknown")
        client_ip = get_client_ip(request)

        # DEBUG logging for proxy requests
        logger.debug(
            f"Proxy: {username} {request.method} {request.path} from {client_ip}"
        )

        # Prepare headers
        headers = dict(request.headers)
        headers["X-Forwarded-User"] = username
        headers["X-Forwarded-For"] = request.remote
        headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", "http")

        # Remove hop-by-hop headers
        for header in [
            "Host",
            "Connection",
            "Keep-Alive",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "TE",
            "Trailers",
            "Transfer-Encoding",
            "Upgrade",
        ]:
            headers.pop(header, None)

        # Make request to target
        timeout = ClientTimeout(total=60)
        async with (
            ClientSession(timeout=timeout) as session,
            session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=await request.read(),
                allow_redirects=False,
                auto_decompress=False,  # Don't auto-decompress, let browser handle it
            ) as resp,
        ):
            # Create streaming response
            response = web.StreamResponse(status=resp.status, headers=resp.headers)

            # Remove problematic headers
            response.headers.pop("Transfer-Encoding", None)

            # Prepare response
            await response.prepare(request)

            # Stream content from target to client
            async for chunk in resp.content.iter_any():
                await response.write(chunk)

            await response.write_eof()
            return response

    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return web.Response(text="Bad Gateway", status=502)


# Middleware


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Authentication middleware"""
    # Skip auth for setup and API endpoints
    if request.path in ["/psetup", "/plogin", "/pregister"] or request.path.startswith(
        "/api/"
    ):
        return await handler(request)

    # Check for valid JWT
    token = request.cookies.get("session")

    if not token:
        client_ip = get_client_ip(request)
        logger.warning(
            f"Missing session token from {client_ip} attempting {request.path}"
        )
        return web.HTTPFound("/plogin")

    payload = verify_jwt(token)
    if not payload:
        # Clear invalid cookie
        client_ip = get_client_ip(request)
        logger.warning(
            f"Invalid/expired session token from {client_ip} attempting {request.path}"
        )
        response = web.HTTPFound("/plogin")
        response.del_cookie("session")
        return response

    # Store username in request
    request["authenticated_user"] = payload["username"]

    return await handler(request)


@web.middleware
async def setup_redirect_middleware(request: web.Request, handler):
    """Redirect to setup if no credentials exist"""
    if cred_store.is_empty() and request.path not in [
        "/psetup",
        "/api/register/begin",
        "/api/register/complete",
    ]:
        return web.HTTPFound("/psetup")

    return await handler(request)


# Application setup


async def cleanup_background_task(app: web.Application):
    """Background task to cleanup expired items"""

    async def cleanup_loop():
        while True:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
                cleanup_expired_items()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    task = asyncio.create_task(cleanup_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app() -> web.Application:
    """Create and configure the application"""
    app = web.Application(middlewares=[setup_redirect_middleware, auth_middleware])

    # Register background cleanup task
    app.cleanup_ctx.append(cleanup_background_task)

    # Add routes
    app.router.add_get("/psetup", handle_setup)
    app.router.add_get("/plogin", handle_login)
    app.router.add_get("/pregister", handle_register_page)

    # API routes
    app.router.add_post("/api/register/begin", handle_register_begin)
    app.router.add_post("/api/register/complete", handle_register_complete)
    app.router.add_post("/api/login/begin", handle_login_begin)
    app.router.add_post("/api/login/complete", handle_login_complete)
    app.router.add_post("/api/register-auth/begin", handle_register_auth_begin)
    app.router.add_post("/api/register-auth/complete", handle_register_auth_complete)

    # Proxy all other requests
    app.router.add_route("*", "/{path:.*}", handle_proxy)

    return app


def main():
    """Main entry point"""
    # Validate JWT secret key
    if not CONFIG["JWT_SECRET_KEY"]:
        print("\nERROR: JWT_SECRET_KEY must be explicitly set in .env file")
        print(
            "Generate a secure key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
        print("Then add to .env: JWT_SECRET_KEY=<generated_key>")
        return

    # Validate key is strong enough (at least 32 bytes when base64url decoded)
    if len(CONFIG["JWT_SECRET_KEY"]) < 43:  # 32 bytes base64url encoded is ~43 chars
        logger.warning("JWT_SECRET_KEY is shorter than recommended 32 bytes (256 bits)")
        print(
            "Generate a new key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )

    # Validate required config
    if (not CONFIG["TARGET_HOST"] or not CONFIG["TARGET_PORT"]) and not CONFIG["TARGET_HOSTS"]:
        logger.error("TARGET_HOST and TARGET_PORT must be set")
        return

    logger.info(
        f"Passkey Proxy starting on {CONFIG['PROXY_LISTEN_HOST']}:{CONFIG['PROXY_LISTEN_PORT']}, proxying to {CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}"
    )
    logger.info(f"Session expiry: {CONFIG['SESSION_EXPIRY_HOURS']} hours")

    if cred_store.is_empty():
        logger.info("No credentials found, first-time setup required at /psetup")
    else:
        logger.info(
            f"Loaded {len(cred_store.credentials)} registered user(s) from {CONFIG['CREDENTIALS_FILE']}"
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
