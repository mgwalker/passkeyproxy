#!/usr/bin/env python3
"""
Passkey-authenticated HTTP Reverse Proxy
Single-file implementation for home/hobby use
"""

import os
import json
import time
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from pathlib import Path

import jwt
from aiohttp import web, ClientSession, ClientTimeout
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)

from dotenv import load_dotenv
load_dotenv()

# Configure logging (errors only)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration from environment variables
CONFIG = {
    'PROXY_LISTEN_HOST': os.getenv('PROXY_LISTEN_HOST', '0.0.0.0'),
    'PROXY_LISTEN_PORT': int(os.getenv('PROXY_LISTEN_PORT', '8080')),
    'TARGET_HOST': os.getenv('TARGET_HOST', 'localhost'),
    'TARGET_PORT': int(os.getenv('TARGET_PORT', '3000')),
    'SESSION_EXPIRY_HOURS': int(os.getenv('SESSION_EXPIRY_HOURS', '24')),
    'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32)),
    'RP_NAME': os.getenv('RP_NAME', 'Passkey Proxy'),
    'CREDENTIALS_FILE': os.getenv('CREDENTIALS_FILE', './credentials.json'),
}

# In-memory challenge storage (challenge_id -> challenge_data)
CHALLENGES: Dict[str, dict] = {}


class CredentialStore:
    """Manages credential storage in JSON file"""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.credentials: List[dict] = []
        self._load()
    
    def _load(self):
        """Load credentials from file"""
        if self.filepath.exists():
            try:
                with open(self.filepath, 'r') as f:
                    data = json.load(f)
                    self.credentials = data.get('credentials', [])
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
                self.credentials = []
        else:
            self.credentials = []
    
    def _save(self):
        """Save credentials to file"""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, 'w') as f:
                json.dump({'credentials': self.credentials}, f, indent=2)
            os.chmod(self.filepath, 0o600)
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
    
    def is_empty(self) -> bool:
        """Check if there are no credentials"""
        return len(self.credentials) == 0
    
    def add_credential(self, credential_id: bytes, public_key: bytes, 
                      username: str, sign_count: int, credential_data: dict):
        """Add a new credential"""
        self.credentials.append({
            'id': bytes_to_base64url(credential_id),
            'public_key': bytes_to_base64url(public_key),
            'sign_count': sign_count,
            'username': username,
            'credential_data': credential_data,
            'created_at': datetime.utcnow().isoformat()
        })
        self._save()
    
    def get_all_credentials(self) -> List[dict]:
        """Get all credentials for authentication"""
        return self.credentials
    
    def get_credential_by_id(self, credential_id: bytes) -> Optional[dict]:
        """Find credential by ID"""
        cred_id_b64 = bytes_to_base64url(credential_id)
        for cred in self.credentials:
            if cred['id'] == cred_id_b64:
                return cred
        return None
    
    def update_sign_count(self, credential_id: bytes, sign_count: int):
        """Update sign count for a credential"""
        cred = self.get_credential_by_id(credential_id)
        if cred:
            cred['sign_count'] = sign_count
            self._save()


# Initialize credential store
cred_store = CredentialStore(CONFIG['CREDENTIALS_FILE'])


def create_jwt(username: str) -> str:
    """Create JWT token for authenticated session"""
    expiry = datetime.utcnow() + timedelta(hours=CONFIG['SESSION_EXPIRY_HOURS'])
    payload = {
        'username': username,
        'exp': expiry,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, CONFIG['JWT_SECRET_KEY'], algorithm='HS256')


def verify_jwt(token: str) -> Optional[dict]:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, CONFIG['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_rp_id(request: web.Request) -> str:
    """Extract RP ID from Host header"""
    host = request.headers.get('Host', 'localhost')
    # Remove port if present
    return host.split(':')[0]


def get_origin(request: web.Request) -> str:
    """Get origin URL"""
    host = request.headers.get('Host', 'localhost')
    scheme = request.headers.get('X-Forwarded-Proto', 'http')
    return f"{scheme}://{host}"


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
</style>
"""


def setup_page() -> str:
    """Initial setup page HTML"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Initial Setup - {CONFIG['RP_NAME']}</title>
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
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{username}})
                }});
                
                if (!beginResp.ok) {{
                    const error = await beginResp.text();
                    throw new Error(error || 'Failed to begin registration');
                }}
                
                const options = await beginResp.json();
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
                    headers: {{'Content-Type': 'application/json'}},
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
                        username
                    }})
                }});
                
                if (!completeResp.ok) {{
                    const error = await completeResp.text();
                    throw new Error(error || 'Failed to complete registration');
                }}
                
                document.getElementById('status').textContent = 'Success! Redirecting...';
                setTimeout(() => window.location.href = '/login', 1000);
                
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


def login_page() -> str:
    """Login page HTML"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign In - {CONFIG['RP_NAME']}</title>
    {DARK_STYLE}
</head>
<body>
    <div class="container">
        <h1>Sign In</h1>
        <p>Authenticate with your passkey</p>
        <div id="error" class="error" style="display:none;"></div>
        <button onclick="authenticate()">Sign in with Passkey</button>
        <a href="/register" class="link">Register New User</a>
        <div id="status" class="status"></div>
    </div>
    <script>
        async function authenticate() {{
            document.getElementById('status').textContent = 'Starting authentication...';
            
            try {{
                // Begin authentication
                const beginResp = await fetch('/api/login/begin', {{
                    method: 'POST'
                }});
                
                if (!beginResp.ok) {{
                    throw new Error('Failed to begin authentication');
                }}
                
                const options = await beginResp.json();
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
                const completeResp = await fetch('/api/login/complete', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
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
                        }}
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


def register_page() -> str:
    """Registration page for new users"""
    return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Register New User - {CONFIG['RP_NAME']}</title>
    {DARK_STYLE}
</head>
<body>
    <div class="container">
        <div id="auth-step">
            <h1>Register New User</h1>
            <p>First, authenticate with your existing passkey</p>
            <div id="error" class="error" style="display:none;"></div>
            <button onclick="authenticateForRegistration()">Authenticate</button>
            <a href="/login" class="link">Back to Login</a>
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
                    method: 'POST'
                }});
                
                if (!beginResp.ok) {{
                    throw new Error('Failed to begin authentication');
                }}
                
                const options = await beginResp.json();
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
                    headers: {{'Content-Type': 'application/json'}},
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
                        }}
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
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{username}})
                }});
                
                if (!beginResp.ok) {{
                    throw new Error('Failed to begin registration');
                }}
                
                const options = await beginResp.json();
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
                    headers: {{'Content-Type': 'application/json'}},
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
                        username
                    }})
                }});
                
                if (!completeResp.ok) {{
                    throw new Error('Failed to complete registration');
                }}
                
                document.getElementById('status2').textContent = 'Success! Redirecting...';
                setTimeout(() => window.location.href = '/login', 1000);
                
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

async def handle_setup(request: web.Request) -> web.Response:
    """Show setup page if no credentials exist"""
    if not cred_store.is_empty():
        return web.HTTPFound('/login')
    return web.Response(text=setup_page(), content_type='text/html')


async def handle_login(request: web.Request) -> web.Response:
    """Show login page"""
    return web.Response(text=login_page(), content_type='text/html')


async def handle_register_page(request: web.Request) -> web.Response:
    """Show registration page"""
    if cred_store.is_empty():
        return web.HTTPFound('/setup')
    return web.Response(text=register_page(), content_type='text/html')


async def handle_register_begin(request: web.Request) -> web.Response:
    """Begin WebAuthn registration"""
    try:
        data = await request.json()
        username = data.get('username', '').strip()
        
        if not username:
            return web.Response(text='Username required', status=400)
        
        rp_id = get_rp_id(request)
        origin = get_origin(request)
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name=CONFIG['RP_NAME'],
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
            'challenge': options.challenge,
            'username': username,
            'timestamp': time.time(),
            'type': 'registration'
        }
        
        # Convert to dict and add challenge_id
        options_dict = json.loads(options_to_json(options))
        options_dict['challenge_id'] = challenge_id
        
        return web.json_response(options_dict)
        
    except Exception as e:
        logger.error(f"Registration begin error: {e}")
        return web.Response(text='Registration failed', status=500)


async def handle_register_complete(request: web.Request) -> web.Response:
    """Complete WebAuthn registration"""
    try:
        data = await request.json()
        credential = data.get('credential')
        username = data.get('username')
        
        if not credential or not username:
            return web.Response(text='Invalid request', status=400)
        
        # Find challenge
        challenge_id = None
        challenge_data = None
        for cid, cdata in CHALLENGES.items():
            if cdata.get('username') == username and cdata.get('type') == 'registration':
                challenge_id = cid
                challenge_data = cdata
                break
        
        if not challenge_data:
            return web.Response(text='Challenge not found', status=400)
        
        # Clean up old challenges
        CHALLENGES.pop(challenge_id, None)
        
        rp_id = get_rp_id(request)
        origin = get_origin(request)
        
        # Verify registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge_data['challenge'],
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        
        # Store credential
        cred_store.add_credential(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            username=username,
            sign_count=verification.sign_count,
            credential_data=credential
        )
        
        return web.Response(text='Registration successful', status=200)
        
    except Exception as e:
        logger.error(f"Registration complete error: {e}")
        return web.Response(text='Registration failed', status=500)


async def handle_login_begin(request: web.Request) -> web.Response:
    """Begin WebAuthn authentication"""
    try:
        if cred_store.is_empty():
            return web.Response(text='No credentials registered', status=400)
        
        rp_id = get_rp_id(request)
        
        # Get all credentials
        credentials = cred_store.get_all_credentials()
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred['id']))
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
            'challenge': options.challenge,
            'timestamp': time.time(),
            'type': 'authentication'
        }
        
        # Convert to dict
        options_dict = json.loads(options_to_json(options))
        options_dict['challenge_id'] = challenge_id
        
        return web.json_response(options_dict)
        
    except Exception as e:
        logger.error(f"Login begin error: {e}")
        return web.Response(text='Authentication failed', status=500)


async def handle_login_complete(request: web.Request) -> web.Response:
    """Complete WebAuthn authentication"""
    try:
        data = await request.json()
        credential = data.get('credential')
        
        if not credential:
            return web.Response(text='Invalid request', status=400)
        
        # Find credential in store
        cred_id = base64url_to_bytes(credential['rawId'])
        stored_cred = cred_store.get_credential_by_id(cred_id)
        
        if not stored_cred:
            return web.Response(text='Credential not found', status=400)
        
        # Find any authentication challenge
        challenge_data = None
        challenge_id = None
        for cid, cdata in CHALLENGES.items():
            if cdata.get('type') == 'authentication':
                challenge_id = cid
                challenge_data = cdata
                break
        
        if not challenge_data:
            return web.Response(text='Challenge not found', status=400)
        
        CHALLENGES.pop(challenge_id, None)
        
        rp_id = get_rp_id(request)
        origin = get_origin(request)
        
        # Verify authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_data['challenge'],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored_cred['public_key']),
            credential_current_sign_count=stored_cred['sign_count'],
        )
        
        # Update sign count
        cred_store.update_sign_count(cred_id, verification.new_sign_count)
        
        # Create JWT
        token = create_jwt(stored_cred['username'])
        
        # Set cookie
        response = web.Response(text='Authentication successful', status=200)
        response.set_cookie(
            'session',
            token,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=CONFIG['SESSION_EXPIRY_HOURS'] * 3600
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Login complete error: {e}")
        return web.Response(text='Authentication failed', status=500)


async def handle_register_auth_begin(request: web.Request) -> web.Response:
    """Begin authentication for registration (same as login)"""
    return await handle_login_begin(request)


async def handle_register_auth_complete(request: web.Request) -> web.Response:
    """Complete authentication for registration (no cookie needed)"""
    try:
        data = await request.json()
        credential = data.get('credential')
        
        if not credential:
            return web.Response(text='Invalid request', status=400)
        
        cred_id = base64url_to_bytes(credential['rawId'])
        stored_cred = cred_store.get_credential_by_id(cred_id)
        
        if not stored_cred:
            return web.Response(text='Credential not found', status=400)
        
        challenge_data = None
        challenge_id = None
        for cid, cdata in CHALLENGES.items():
            if cdata.get('type') == 'authentication':
                challenge_id = cid
                challenge_data = cdata
                break
        
        if not challenge_data:
            return web.Response(text='Challenge not found', status=400)
        
        CHALLENGES.pop(challenge_id, None)
        
        rp_id = get_rp_id(request)
        origin = get_origin(request)
        
        # Verify authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge_data['challenge'],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored_cred['public_key']),
            credential_current_sign_count=stored_cred['sign_count'],
        )
        
        cred_store.update_sign_count(cred_id, verification.new_sign_count)
        
        # Return success without setting cookie
        return web.Response(text='Authentication successful', status=200)
        
    except Exception as e:
        logger.error(f"Register auth complete error: {e}")
        return web.Response(text='Authentication failed', status=500)


async def handle_proxy(request: web.Request) -> web.Response:
    """Proxy requests to target application"""
    try:
        # Build target URL
        target_url = f"http://{CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}{request.path_qs}"
        
        # Get authenticated username
        username = request.get('authenticated_user', 'unknown')
        
        # Prepare headers
        headers = dict(request.headers)
        headers['X-Forwarded-User'] = username
        headers['X-Forwarded-For'] = request.remote
        headers['X-Forwarded-Proto'] = request.headers.get('X-Forwarded-Proto', 'http')
        
        # Remove hop-by-hop headers
        for header in ['Host', 'Connection', 'Keep-Alive', 'Proxy-Authenticate',
                      'Proxy-Authorization', 'TE', 'Trailers', 'Transfer-Encoding', 'Upgrade']:
            headers.pop(header, None)
        
        # Make request to target
        timeout = ClientTimeout(total=60)
        async with ClientSession(timeout=timeout) as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=await request.read(),
                allow_redirects=False,
                auto_decompress=False  # Don't auto-decompress, let browser handle it
            ) as resp:
                # Create streaming response
                response = web.StreamResponse(status=resp.status, headers=resp.headers)
                
                # Remove problematic headers
                response.headers.pop('Transfer-Encoding', None)
                
                # Prepare response
                await response.prepare(request)
                
                # Stream content from target to client
                async for chunk in resp.content.iter_any():
                    await response.write(chunk)
                
                await response.write_eof()
                return response
    
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return web.Response(text='Bad Gateway', status=502)


# Middleware

@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Authentication middleware"""
    # Skip auth for setup and API endpoints
    if request.path in ['/setup', '/login', '/register'] or request.path.startswith('/api/'):
        return await handler(request)
    
    # Check for valid JWT
    token = request.cookies.get('session')
    
    if not token:
        return web.HTTPFound('/login')
    
    payload = verify_jwt(token)
    if not payload:
        # Clear invalid cookie
        response = web.HTTPFound('/login')
        response.del_cookie('session')
        return response
    
    # Store username in request
    request['authenticated_user'] = payload['username']
    
    return await handler(request)


@web.middleware
async def setup_redirect_middleware(request: web.Request, handler):
    """Redirect to setup if no credentials exist"""
    if cred_store.is_empty() and request.path not in ['/setup', '/api/register/begin', '/api/register/complete']:
        return web.HTTPFound('/setup')
    
    return await handler(request)


# Application setup

def create_app() -> web.Application:
    """Create and configure the application"""
    app = web.Application(middlewares=[setup_redirect_middleware, auth_middleware])
    
    # Add routes
    app.router.add_get('/setup', handle_setup)
    app.router.add_get('/login', handle_login)
    app.router.add_get('/register', handle_register_page)
    
    # API routes
    app.router.add_post('/api/register/begin', handle_register_begin)
    app.router.add_post('/api/register/complete', handle_register_complete)
    app.router.add_post('/api/login/begin', handle_login_begin)
    app.router.add_post('/api/login/complete', handle_login_complete)
    app.router.add_post('/api/register-auth/begin', handle_register_auth_begin)
    app.router.add_post('/api/register-auth/complete', handle_register_auth_complete)
    
    # Proxy all other requests
    app.router.add_route('*', '/{path:.*}', handle_proxy)
    
    return app


def main():
    """Main entry point"""
    # Validate required config
    if not CONFIG['TARGET_HOST'] or not CONFIG['TARGET_PORT']:
        logger.error("TARGET_HOST and TARGET_PORT must be set")
        return
    
    print(f"Starting Passkey Proxy on {CONFIG['PROXY_LISTEN_HOST']}:{CONFIG['PROXY_LISTEN_PORT']}")
    print(f"Proxying to {CONFIG['TARGET_HOST']}:{CONFIG['TARGET_PORT']}")
    print(f"Session expiry: {CONFIG['SESSION_EXPIRY_HOURS']} hours")
    print(f"Credentials file: {CONFIG['CREDENTIALS_FILE']}")
    
    if cred_store.is_empty():
        print("\nNo credentials found. Please visit /setup to register the first user.")
    else:
        print(f"\nFound {len(cred_store.credentials)} registered user(s).")
    
    app = create_app()
    web.run_app(
        app,
        host=CONFIG['PROXY_LISTEN_HOST'],
        port=CONFIG['PROXY_LISTEN_PORT'],
        print=None  # Suppress aiohttp startup messages
    )


if __name__ == '__main__':
    main()
