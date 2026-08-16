#!/usr/bin/env python3
"""
Passkey-authenticated HTTP Reverse Proxy
Single-file implementation for home/hobby use
"""

import json
import os

from dotenv import load_dotenv

load_dotenv()

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

try:  # noqa: SIM105
    hosts = json.loads(CONFIG["TARGET_HOST"])
    CONFIG["TARGET_HOST"] = None
    CONFIG["TARGET_HOSTS"] = {host.lower(): target for host, target in hosts.items()}
except json.JSONDecodeError:
    pass
