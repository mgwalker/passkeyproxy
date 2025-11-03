# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passkey-authenticated HTTP reverse proxy - a single-file Python implementation for home/hobby use. The proxy sits in front of a target application and requires WebAuthn (passkey) authentication before allowing access.

**Security Hardening**: As of the latest version, the proxy includes comprehensive security measures: HMAC-based CSRF protection, rate limiting, challenge expiration, strict SameSite cookies, mandatory JWT secret validation, and security/audit logging.

## Architecture

### Single-File Design
The entire application is contained in `main.py` (~1568 lines). This design choice prioritizes simplicity and ease of deployment for home/hobby use.

### Core Components

1. **CredentialStore** (lines 72-138)
   - Manages passkey credentials in a JSON file
   - Stores credential ID, public key, sign count, username, and metadata
   - File permissions set to 0o600 for security

2. **Security Layer** (lines 146-240)
   - CSRF token generation and validation (HMAC-SHA256 based, 10-minute expiry, reusable per page session)
   - Challenge timestamp validation (60-second expiry)
   - Rate limiting decorator (IP-based, configurable limits)
   - Background cleanup task for expired items
   - Client IP extraction with X-Forwarded-For support

3. **Authentication Flow**
   - Uses WebAuthn for passkey registration and authentication
   - JWT tokens for session management (stored in HTTP-only, Strict SameSite cookies)
   - Two-step registration: existing users must authenticate before registering new users
   - All state-changing endpoints validate CSRF tokens

4. **Middleware Stack** (lines 1328-1356)
   - `setup_redirect_middleware`: Redirects to /psetup if no credentials exist
   - `auth_middleware`: Validates JWT tokens, redirects unauthenticated users to /plogin
   - Both middlewares skip auth/setup pages and API endpoints

5. **Proxy Handler** (lines 1173-1326)
   - Forwards all authenticated requests to TARGET_HOST:TARGET_PORT
   - Adds `X-Forwarded-User`, `X-Forwarded-For`, `X-Forwarded-Proto` headers
   - Streams responses from target to client
   - Supports WebSocket connections

6. **Challenge Management**
   - In-memory dictionary `CHALLENGES` stores WebAuthn challenges (line 67)
   - Each challenge includes: challenge bytes, username (for registration), timestamp, and type
   - Challenges expire after 60 seconds and are single-use
   - Background cleanup task runs every 30 seconds
   - Maximum 1000 challenges to prevent memory exhaustion

### Configuration

All configuration is loaded from environment variables (lines 44-53):
- `PROXY_LISTEN_HOST/PORT`: Where the proxy listens
- `TARGET_HOST/PORT`: Backend application to protect
- `JWT_SECRET_KEY`: **REQUIRED** - Session token signing key (must be explicitly set, minimum 32 bytes)
- `SESSION_EXPIRY_HOURS`: How long sessions last
- `RP_NAME`: WebAuthn relying party name
- `CREDENTIALS_FILE`: Where to store passkey credentials
- `LOG_LEVEL`: Logging verbosity (default: INFO, options: DEBUG/INFO/WARNING/ERROR)

Configuration is loaded from `.env` file via `python-dotenv` (line 36-37).

### Security Constants (lines 53-64)

- `CHALLENGE_EXPIRY_SECONDS`: 60 seconds
- `CSRF_TOKEN_EXPIRY_SECONDS`: 600 seconds (10 minutes)
- `MAX_CHALLENGES`: 1000 (memory limit)
- `MAX_CSRF_TOKENS`: 1000 (memory limit)
- `CLEANUP_INTERVAL_SECONDS`: 30 seconds
- Rate limiting: BEGIN (10/min), COMPLETE (20/min), PAGES (30/min)
- `RATE_LIMIT_WINDOW_SECONDS`: 60 seconds

### Routes

**Pages:**
- `/psetup` - Initial admin registration (only shown when no credentials exist)
- `/plogin` - Passkey authentication
- `/pregister` - New user registration (requires existing user auth first)

**API Endpoints:**
- `/api/register/begin` & `/api/register/complete` - WebAuthn registration ceremony
- `/api/login/begin` & `/api/login/complete` - WebAuthn authentication ceremony
- `/api/register-auth/begin` & `/api/register-auth/complete` - Auth check before new user registration

**Proxy:**
- `/{path:.*}` - All other requests are proxied to target application

### WebAuthn Implementation

- Uses `py_webauthn` library (imported as `webauthn`)
- RP ID extracted from Host header
- Origin derived from Host + X-Forwarded-Proto headers
- Supports resident keys (preferred) and user verification (preferred)
- Sign count validation to detect credential cloning attacks

### Logging Implementation

The application includes comprehensive security/audit logging:

**Log Levels:**
- **INFO** (default): Authentication success/failure, user registration, session issues, credential operations, startup/config
- **WARNING**: CSRF failures, rate limits, challenge validation errors, sign count anomalies, memory limit enforcement
- **DEBUG**: Proxy requests, WebSocket lifecycle, cleanup operations (verbose)
- **ERROR**: Exceptions and critical errors

**Key Features:**
- All client IP addresses use `get_client_ip()` helper which respects X-Forwarded-For header
- Credential IDs truncated to first 8 chars via `format_credential_id()` helper
- Old-school Unix text format (no JSON)
- Single line per event, grep-friendly
- Log format: `%(asctime)s - %(levelname)s - %(message)s`

**Logging Configuration:**
- Configured at startup (lines 40-44) with LOG_LEVEL env var
- Default level: INFO
- Structured for security auditing without excessive verbosity

## Development Commands

### Run the proxy server
```bash
python main.py
```

### Install dependencies
```bash
# Using uv (preferred - this project uses uv)
uv sync

# Using pip
pip install -r requirements.txt  # Note: project uses pyproject.toml, not requirements.txt
```

### Run with specific Python version
The project requires Python >=3.11 (specified in pyproject.toml).

## Important Notes

- **Single-file architecture**: All code is in `main.py` (~1568 lines with logging) - do not split into modules unless explicitly requested
- **Security credentials**: `credentials.json` and `.env` contain secrets and should never be committed
- **In-memory state**: Challenges, CSRF tokens, and rate limits stored in-memory - lost on restart (acceptable for this use case)
- **No database**: Uses JSON file storage for simplicity
- **Logging**: Configured to INFO level by default (lines 40-44) for security/audit events. Use LOG_LEVEL env var to adjust (DEBUG/INFO/WARNING/ERROR)
- **Session cookies**: HTTP-only, Secure, and SameSite=Strict flags set
- **CSRF protection**: All state-changing endpoints require HMAC-based CSRF token validation via HTTP headers. Tokens are cryptographically bound using HMAC-SHA256 with JWT_SECRET_KEY, reusable per page session, and expire after 10 minutes
- **Rate limiting**: Applied to all page and API endpoints using decorator pattern
- **Background tasks**: Cleanup task registered with app.cleanup_ctx for automatic lifecycle management
- **JWT validation**: Application fails fast on startup if JWT_SECRET_KEY is not set or too weak
