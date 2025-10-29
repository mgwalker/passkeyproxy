# Docker Deployment Guide

This guide explains how to run the Passkey Proxy using Docker.

## Quick Start with Docker Compose

1. **Generate a JWT secret key:**
   ```bash
   openssl rand -base64 32
   ```

2. **Create a `.env` file:**
   ```bash
   cat > .env << 'EOF'
   JWT_SECRET_KEY=your-generated-secret-key-here
   TARGET_HOST=host.docker.internal
   TARGET_PORT=3000
   SESSION_EXPIRY_HOURS=24
   RP_NAME=Passkey Proxy
   EOF
   ```

3. **Start the service:**
   ```bash
   docker-compose up -d
   ```

4. **Access the proxy:**
   - Open http://localhost:8080/psetup
   - Register the first admin user with a passkey

5. **View logs:**
   ```bash
   docker-compose logs -f passkeyproxy
   ```

## Manual Docker Commands

### Build the image:
```bash
docker build -t passkeyproxy .
```

### Run the container:
```bash
# Create data directory for persistent storage
mkdir -p ./data

# Run the container
docker run -d \
  --name passkeyproxy \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e TARGET_HOST=host.docker.internal \
  -e TARGET_PORT=3000 \
  -e JWT_SECRET_KEY=$(openssl rand -base64 32) \
  -e SESSION_EXPIRY_HOURS=24 \
  -e RP_NAME="Passkey Proxy" \
  --add-host host.docker.internal:host-gateway \
  passkeyproxy
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_LISTEN_HOST` | Interface to bind to | `0.0.0.0` |
| `PROXY_LISTEN_PORT` | Port to listen on | `8080` |
| `TARGET_HOST` | Backend application hostname | `localhost` |
| `TARGET_PORT` | Backend application port | `3000` |
| `JWT_SECRET_KEY` | Secret key for JWT signing | Auto-generated |
| `SESSION_EXPIRY_HOURS` | Session duration in hours | `24` |
| `RP_NAME` | WebAuthn relying party name | `Passkey Proxy` |
| `CREDENTIALS_FILE` | Path to credentials storage | `/app/data/credentials.json` |

### Volumes

- `/app/data` - Persistent storage for `credentials.json`

Mount this volume to preserve credentials across container restarts.

## Production Considerations

### 1. Use HTTPS

The proxy should be deployed behind a reverse proxy (nginx, Traefik, Caddy) that handles HTTPS:

```yaml
# Example with Traefik
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.passkeyproxy.rule=Host(`proxy.example.com`)"
  - "traefik.http.routers.passkeyproxy.entrypoints=websecure"
  - "traefik.http.routers.passkeyproxy.tls.certresolver=letsencrypt"
```

### 2. Set a Secure JWT Secret

Never use the auto-generated JWT secret in production. Set a strong random key:

```bash
JWT_SECRET_KEY=$(openssl rand -base64 32)
```

### 3. Backup Credentials

Regularly backup the `/app/data/credentials.json` file:

```bash
docker cp passkeyproxy:/app/data/credentials.json ./backup/
```

### 4. Resource Limits

Add resource limits to prevent resource exhaustion:

```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
    reservations:
      cpus: '0.25'
      memory: 256M
```

## Proxying to Different Target Applications

### To a service on the host machine:
```yaml
environment:
  - TARGET_HOST=host.docker.internal
  - TARGET_PORT=3000
extra_hosts:
  - "host.docker.internal:host-gateway"
```

### To another Docker container:
```yaml
environment:
  - TARGET_HOST=myapp
  - TARGET_PORT=8080
networks:
  - app-network
```

### To an external service:
```yaml
environment:
  - TARGET_HOST=api.example.com
  - TARGET_PORT=443
```

## Troubleshooting

### Check container logs:
```bash
docker-compose logs -f passkeyproxy
```

### Verify container is running:
```bash
docker ps | grep passkeyproxy
```

### Test connectivity to target:
```bash
docker exec passkeyproxy curl -f http://${TARGET_HOST}:${TARGET_PORT}
```

### Inspect container:
```bash
docker exec -it passkeyproxy /bin/bash
```

### Reset credentials:
```bash
# Stop container
docker-compose down

# Remove credentials file
rm -f ./data/credentials.json

# Restart container
docker-compose up -d
```

## Security Notes

- The container runs as a non-root user (`proxyuser`)
- Credentials file is stored with restricted permissions
- HTTP-only cookies are used for session management
- WebAuthn provides phishing-resistant authentication
- JWT secrets should never be committed to version control
