# Dockerfile for Passkey-authenticated HTTP Reverse Proxy
FROM python:3.11-slim

# Install uv for faster dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash proxyuser && \
    mkdir -p /app/data && \
    chown -R proxyuser:proxyuser /app

# Copy dependency files
COPY --chown=proxyuser:proxyuser pyproject.toml ./

# Install dependencies using uv
RUN uv pip install --system --no-cache -r pyproject.toml

# Copy application code
COPY --chown=proxyuser:proxyuser main.py ./

# Switch to non-root user
USER proxyuser

# Create volume mount point for persistent data
VOLUME ["/app/data"]

# Expose default proxy port
EXPOSE 8080

# Set default environment variables
ENV PROXY_LISTEN_HOST=0.0.0.0 \
    PROXY_LISTEN_PORT=8080 \
    CREDENTIALS_FILE=/app/data/credentials.json

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/login').read()" || exit 1

# Run the application
CMD ["python", "main.py"]
