#!/usr/bin/env python3
"""
Passkey-authenticated HTTP Reverse Proxy
Single-file implementation for home/hobby use
"""

import os
import tomllib
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Load configuration from environment variables
_ENV_CONFIG = {
    "PROXY_LISTEN_HOST": os.getenv("PROXY_LISTEN_HOST", "0.0.0.0"),
    "PROXY_LISTEN_PORT": int(os.getenv("PROXY_LISTEN_PORT", "8080")),
    "TARGET_HOST": os.getenv("TARGET_HOST", "localhost:3000"),
    "SESSION_EXPIRY_HOURS": int(os.getenv("SESSION_EXPIRY_HOURS", "24")),
    "JWT_SECRET_KEY": os.getenv(
        "JWT_SECRET_KEY"
    ),  # No fallback - must be explicitly set
    "RP_NAME": os.getenv("RP_NAME", "Passkey Proxy"),
    "CREDENTIALS_FILE": os.getenv("CREDENTIALS_FILE", "./credentials.json"),
    "CONFIG_FILE": os.getenv("CONFIG_FILE", None),
}

_TOML_CONFIG = {}
if _ENV_CONFIG["CONFIG_FILE"]:
    with open(Path(_ENV_CONFIG["CONFIG_FILE"]), "rb") as toml:
        _TOML_CONFIG = tomllib.load(toml)

CONFIG = {**_ENV_CONFIG, **_TOML_CONFIG}

if isinstance(CONFIG.get("TARGET_HOST"), str):
    CONFIG["TARGET_HOST"] = [
        {"HOST": "*", "TARGET": f"{CONFIG['TARGET_HOST']}", "AUTH_REQUIRED": True}
    ]

CONFIG["TARGET_HOST"] = {
    target.get("HOST", "*").lower(): {
        "HOST": "*",
        "AUTH_REQUIRED": True,
        "AUTH_HEADER": "X-Forwarded-User",
        **target,
    }
    for target in CONFIG["TARGET_HOST"]
}
