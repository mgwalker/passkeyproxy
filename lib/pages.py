from lib.config import CONFIG
from lib.style import DARK_STYLE

# Lots of lines are too long here, and that's fine. Ignore them all.
# ruff: noqa: E501


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
                const beginResp = await fetch('/ppauth/api/register/begin', {{
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
                const completeResp = await fetch('/ppauth/api/register/complete', {{
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
                setTimeout(() => window.location.href = '/ppauth/login', 1000);
                
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
        <a href="/ppauth/register" class="link">Register New User</a>
        <div id="status" class="status"></div>
    </div>
    <script>
        async function authenticate() {{
            document.getElementById('status').textContent = 'Starting authentication...';
            
            try {{
                // Begin authentication
                const beginResp = await fetch('/ppauth/api/login/begin', {{
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
                const completeResp = await fetch('/ppauth/api/login/complete', {{
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
            <a href="/ppauth/login" class="link">Back to Login</a>
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
                const beginResp = await fetch('/ppauth/api/register-auth/begin', {{
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
                
                const completeResp = await fetch('/ppauth/api/register-auth/complete', {{
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
                const beginResp = await fetch('/ppauth/api/register/begin', {{
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
                
                const completeResp = await fetch('/ppauth/api/register/complete', {{
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
                setTimeout(() => window.location.href = '/ppauth/login', 1000);
                
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
