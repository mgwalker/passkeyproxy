# Dockerfile for Passkey-authenticated HTTP Reverse Proxy
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./

# Install dependencies using pip
RUN pip install --no-cache .

# Copy application code
COPY --link lib ./lib
COPY --link main.py ./

# Create volume mount point for persistent data
VOLUME ["/app/data"]

# Expose default proxy port
EXPOSE 8080

# Set default environment variables
ENV PROXY_LISTEN_HOST=0.0.0.0 \
    PROXY_LISTEN_PORT=8080 \
    CREDENTIALS_FILE=/app/data/credentials.json

# Health check
HEALTHCHECK --interval=600s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/login').read()" || exit 1

# Run the application
CMD ["python", "main.py"]
