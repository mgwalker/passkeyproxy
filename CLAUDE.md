# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passkey-authenticated HTTP reverse proxy - a single-file Python implementation for home/hobby use. The proxy sits in front of a target application and requires WebAuthn (passkey) authentication before allowing access.

## Architecture

### Single-File Design
The entire application is contained in `main.py` (~1050 lines). This design choice prioritizes simplicity and ease of deployment for home/hobby use.

### Core Components

1. **CredentialStore** (lines 56-121)
   - Manages passkey credentials in a JSON file
   - Stores credential ID, public key, sign count, username, and metadata
   - File permissions set to 0o600 for security

2. **Authentication Flow**
   - Uses WebAuthn for passkey registration and authentication
   - JWT tokens for session management (stored in HTTP-only cookies)
   - Two-step registration: existing users must authenticate before registering new users

3. **Middleware Stack** (lines 959-991)
   - `setup_redirect_middleware`: Redirects to /setup if no credentials exist
   - `auth_middleware`: Validates JWT tokens, redirects unauthenticated users to /login
   - Both middlewares skip auth/setup pages and API endpoints

4. **Proxy Handler** (lines 905-954)
   - Forwards all authenticated requests to TARGET_HOST:TARGET_PORT
   - Adds `X-Forwarded-User`, `X-Forwarded-For`, `X-Forwarded-Proto` headers
   - Streams responses from target to client

5. **Challenge Management**
   - In-memory dictionary `CHALLENGES` stores WebAuthn challenges (line 53)
   - Each challenge includes: challenge bytes, username (for registration), timestamp, and type
   - Challenges are single-use and cleaned up after verification

### Configuration

All configuration is loaded from environment variables (lines 40-50):
- `PROXY_LISTEN_HOST/PORT`: Where the proxy listens
- `TARGET_HOST/PORT`: Backend application to protect
- `JWT_SECRET_KEY`: Session token signing key
- `SESSION_EXPIRY_HOURS`: How long sessions last
- `RP_NAME`: WebAuthn relying party name
- `CREDENTIALS_FILE`: Where to store passkey credentials

Configuration is loaded from `.env` file via `python-dotenv` (line 33-34).

### Routes

**Pages:**
- `/setup` - Initial admin registration (only shown when no credentials exist)
- `/login` - Passkey authentication
- `/register` - New user registration (requires existing user auth first)

**API Endpoints:**
- `/api/register/begin` & `/api/register/complete` - WebAuthn registration ceremony
- `/api/login/begin` & `/api/login/complete` - WebAuthn authentication ceremony
- `/api/register-auth/begin` & `/api/register-auth/complete` - Auth check before new user registration

**Proxy:**
- `/{path:.*}` - All other requests are proxied to target application

### WebAuthn Implementation

- Uses `py_webauthn` library (imported as `webauthn`)
- RP ID extracted from Host header (lines 150-154)
- Origin derived from Host + X-Forwarded-Proto headers (lines 157-161)
- Supports resident keys (preferred) and user verification (preferred)
- Sign count validation to detect credential cloning attacks

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

- **Single-file architecture**: All code is in `main.py` - do not split into modules unless explicitly requested
- **Security credentials**: `credentials.json` and `.env` contain secrets and should never be committed
- **Challenge storage**: Currently in-memory only - all challenges are lost on restart
- **No database**: Uses JSON file storage for simplicity
- **Logging**: Configured to ERROR level only (line 37) to reduce noise
- **Session cookies**: Secure flag set to True (line 837) - requires HTTPS in production
