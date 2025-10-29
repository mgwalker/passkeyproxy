# Passkey Proxy

A lightweight, passkey-authenticated HTTP reverse proxy for securing home and hobby applications. Add enterprise-grade WebAuthn (passkey) authentication to any web application without modifying its code.

## Features

- 🔐 **Passkey Authentication** - Secure, passwordless authentication using WebAuthn
- 📄 **Single-File Design** - Entire proxy in one Python file for easy deployment
- 🔒 **Zero Trust** - No access without valid authentication
- 🌐 **Universal Proxy** - Works with any HTTP backend application
- 📱 **Multi-Device Support** - Use hardware keys, phones, or platform authenticators
- ⏰ **Session Management** - Configurable JWT-based sessions
- 👥 **Multi-User** - Support for multiple authenticated users
- 📊 **Streaming Support** - Handles large responses and streaming content
- 🌙 **Dark Mode UI** - Clean, modern authentication interface

## Use Cases

- Secure access to self-hosted applications (Jellyfin, Home Assistant, etc.)
- Add authentication to applications without built-in auth
- Replace basic auth with modern passkey authentication
- Protect internal tools and dashboards
- Secure development servers exposed to the internet

## Quick Start

### Prerequisites

- Python 3.11 or higher
- A backend application to protect
- HTTPS setup (required for WebAuthn in production)

### Installation

1. **Clone or download this repository**

```bash
git clone <your-repo-url>
cd passkeyproxy
```

2. **Install dependencies using uv (recommended)**

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync
```

Or using pip:

```bash
pip install -r <(cat pyproject.toml | grep -A 100 "dependencies = \[" | grep "\"" | sed 's/[", ]//g')
# Or manually:
pip install aiohttp pyjwt python-dotenv webauthn
```

3. **Configure the proxy**

Create a `.env` file:

```bash
# Required: Target application to protect
TARGET_HOST=localhost
TARGET_PORT=3000

# Optional: Proxy listening configuration
PROXY_LISTEN_HOST=0.0.0.0
PROXY_LISTEN_PORT=8080

# Optional: Session and security
SESSION_EXPIRY_HOURS=24
JWT_SECRET_KEY=your-secret-key-here  # Generated automatically if not set
RP_NAME="My Passkey Proxy"

# Optional: Credential storage
CREDENTIALS_FILE=./credentials.json
```

4. **Run the proxy**

```bash
# Using uv
uv run python main.py

# Or directly with Python
python main.py
```

5. **Register the first user**

- Navigate to `http://your-proxy-address:8080/psetup`
- Enter a username
- Follow your browser's passkey registration flow
- You'll be redirected to the login page

6. **Login and access your application**

- Visit `http://your-proxy-address:8080/plogin`
- Authenticate with your passkey
- You'll be proxied to your protected application

## Configuration

All configuration is done via environment variables (or `.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_HOST` | `localhost` | Backend application hostname |
| `TARGET_PORT` | `3000` | Backend application port |
| `PROXY_LISTEN_HOST` | `0.0.0.0` | Address for proxy to listen on |
| `PROXY_LISTEN_PORT` | `8080` | Port for proxy to listen on |
| `SESSION_EXPIRY_HOURS` | `24` | How long sessions remain valid |
| `JWT_SECRET_KEY` | Auto-generated | Secret key for signing session tokens |
| `RP_NAME` | `Passkey Proxy` | Display name shown during authentication |
| `CREDENTIALS_FILE` | `./credentials.json` | Where to store passkey credentials |

## Architecture

### How It Works

```
User Request  Passkey Proxy  Authentication Check  Target Application
                                                             
                      Proxied Response 
```

1. User requests are intercepted by the proxy
2. Authentication status is checked via JWT session cookie
3. Unauthenticated requests are redirected to login
4. Authenticated requests are forwarded to the target application
5. Responses are streamed back to the user

### Components

- **WebAuthn Flow**: Registration and authentication using the Web Authentication API
- **JWT Sessions**: Secure session tokens stored in HTTP-only cookies
- **Credential Store**: Persistent JSON storage for passkey credentials
- **Middleware**: Request filtering and authentication enforcement
- **Proxy Handler**: HTTP request forwarding with header enrichment

### Security Features

- **HTTP-Only Cookies**: Session tokens not accessible to JavaScript
- **Challenge-Response**: Cryptographic challenge verification for each authentication
- **Sign Count Validation**: Detects credential cloning attacks
- **Resident Keys**: Supports discoverable credentials for better UX
- **File Permissions**: Credential file restricted to owner-only (0600)

## User Management

### Register Additional Users

After the initial setup, existing authenticated users can register new users:

1. Log in with an existing passkey
2. Navigate to `/pregister`
3. Authenticate again (security verification)
4. Enter the new username
5. Complete passkey registration for the new user

### Credential Storage

Credentials are stored in `credentials.json` (configurable). Each credential includes:

- Credential ID (public)
- Public key
- Sign count (for clone detection)
- Username
- Creation timestamp

⚠️ **Important**: Back up this file regularly. Loss means all users must re-register.

## Production Deployment

### HTTPS Setup

WebAuthn requires HTTPS in production. Options:

1. **Reverse Proxy** (Recommended)
   ```
   Internet  Caddy/Nginx (HTTPS)  Passkey Proxy (HTTP)  Target App
   ```

2. **Caddy Example**
   ```
   your-domain.com {
       reverse_proxy localhost:8080
   }
   ```

3. **Nginx Example**
   ```nginx
   server {
       listen 443 ssl;
       server_name your-domain.com;

       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Systemd Service

Create `/etc/systemd/system/passkeyproxy.service`:

```ini
[Unit]
Description=Passkey Proxy
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/passkeyproxy
Environment=PATH=/path/to/venv/bin
ExecStart=/path/to/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable passkeyproxy
sudo systemctl start passkeyproxy
sudo systemctl status passkeyproxy
```

### Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install uv

# Copy project files
COPY pyproject.toml uv.lock ./
COPY main.py ./

# Install dependencies
RUN uv sync --frozen

# Expose proxy port
EXPOSE 8080

# Run the proxy
CMD ["uv", "run", "python", "main.py"]
```

Build and run:

```bash
docker build -t passkeyproxy .
docker run -d \
  --name passkeyproxy \
  -p 8080:8080 \
  -v $(pwd)/credentials.json:/app/credentials.json \
  -v $(pwd)/.env:/app/.env \
  passkeyproxy
```

### Environment Considerations

- **JWT_SECRET_KEY**: Use a strong, unique secret in production
- **File Permissions**: Ensure `credentials.json` and `.env` are protected
- **Backups**: Regularly backup `credentials.json`
- **Logging**: Currently set to ERROR level only; adjust if needed
- **Challenge Storage**: In-memory only; challenges are lost on restart (this is acceptable as they're short-lived)

## Advanced Usage

### Headers Forwarded to Target

The proxy adds these headers to all proxied requests:

- `X-Forwarded-User`: Authenticated username
- `X-Forwarded-For`: Client IP address
- `X-Forwarded-Proto`: Original protocol (http/https)

Your backend application can use these for user identification and logging.

### Session Management

Sessions are valid for `SESSION_EXPIRY_HOURS`. After expiry, users must re-authenticate. To invalidate a session:

- Delete the `session` cookie (client-side)
- User will be redirected to login on next request

### Multiple Target Applications

To protect multiple applications, run multiple instances with different:

- `PROXY_LISTEN_PORT`
- `TARGET_HOST` / `TARGET_PORT`
- `CREDENTIALS_FILE` (to maintain separate user lists)

## Troubleshooting

### "Registration failed" or "Authentication failed"

- **HTTPS Required**: Ensure you're using HTTPS in production
- **Host Header**: Verify your reverse proxy forwards the correct `Host` header
- **Browser Compatibility**: Use a modern browser with WebAuthn support
- **Permissions**: Check credential file permissions (should be 0600)

### "Challenge not found"

- Challenge expired (short-lived by design)
- Application restarted (challenges are in-memory)
- **Solution**: Refresh the page and try again

### Proxy not forwarding requests

- **Check target**: Verify `TARGET_HOST` and `TARGET_PORT` are correct
- **Network**: Ensure proxy can reach the target application
- **Logs**: Check console output for error messages
- **Authentication**: Verify you're properly authenticated

### Can't access /psetup page

- Credentials already exist (`credentials.json` is not empty)
- **Solution**: Delete `credentials.json` to reset (⚠️ all users will need to re-register)

## Security Considerations

### What This Protects

✓ Unauthorized access to your application
✓ Weak password vulnerabilities
✓ Credential stuffing attacks
✓ Session hijacking (with proper HTTPS setup)

### What This Doesn't Protect

✗ Vulnerabilities in your target application
✗ Attacks after authentication (authorization is application-dependent)
✗ Physical access to authenticated devices
✗ Compromised JWT_SECRET_KEY

### Best Practices

1. **Use HTTPS in production** - Non-negotiable for security
2. **Strong JWT secret** - Use a cryptographically random key
3. **Regular backups** - Don't lose your credentials file
4. **Monitor logs** - Watch for unusual authentication patterns
5. **Update dependencies** - Keep Python packages current
6. **Limit exposure** - Use firewall rules to restrict access
7. **Separate credentials** - Use different `CREDENTIALS_FILE` for each application

## Limitations

- **Single-file design**: Optimized for simplicity over scalability
- **In-memory challenges**: Lost on restart (acceptable for WebAuthn use case)
- **File-based storage**: Not suitable for thousands of users
- **No built-in rate limiting**: Add via reverse proxy if needed
- **No audit logging**: Only error logs by default

## Contributing

This is a single-file project designed for simplicity. When contributing:

- Keep everything in `main.py` unless there's a compelling reason to split
- Maintain the minimal dependency list
- Test with various authenticators (hardware keys, phones, platform)
- Ensure HTTPS compatibility

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Support

For issues, questions, or contributions, please [open an issue](your-repo-url/issues).

## Acknowledgments

- Built with [py_webauthn](https://github.com/duo-labs/py_webauthn)
- Uses [aiohttp](https://docs.aiohttp.org/) for async HTTP handling
- Inspired by the need for simple, secure self-hosted authentication
