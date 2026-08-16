import hashlib
import hmac
import secrets
import time

from lib.config import CONFIG
from lib.logger import logger

_CSRF_TOKENS: dict[str, float] = {}  # csrf_token_id -> timestamp
_CSRF_TOKEN_EXPIRY_SECONDS = 600  # CSRF tokens expire after 10 minutes
_MAX_CSRF_TOKENS = 1000  # Maximum number of CSRF tokens in memory


def generate_csrf_token() -> tuple[str, str]:
    """Generate CSRF token with HMAC signature"""
    token_id = secrets.token_urlsafe(32)
    timestamp = time.time()

    # Compute HMAC signature over token_id + timestamp
    message = f"{token_id}:{timestamp}".encode()
    token_value = hmac.new(
        CONFIG["JWT_SECRET_KEY"].encode("utf-8"), message, hashlib.sha256
    ).hexdigest()

    _CSRF_TOKENS[token_id] = timestamp
    return (token_id, token_value)


def get_csrf_token(token_id) -> float:
    timestamp = _CSRF_TOKENS.get(token_id)
    if timestamp and time.time() - timestamp > _CSRF_TOKEN_EXPIRY_SECONDS:
        _CSRF_TOKENS.pop(token_id)
        return None

    return timestamp


def validate_csrf_token(token_id: str, token_value: str) -> bool:
    """Validate CSRF token with HMAC verification (reusable per page session)"""
    if not token_id or not token_value:
        return False

    # Check if token exists
    timestamp = get_csrf_token(token_id)
    if timestamp is None:
        return False

    # Recompute HMAC and verify
    message = f"{token_id}:{timestamp}".encode()
    expected_value = hmac.new(
        CONFIG["JWT_SECRET_KEY"].encode("utf-8"), message, hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(token_value, expected_value)


# Cleanup expired CSRF tokens
def clear_expired_csrf_tokens():
    current_time = time.time()
    expired_csrf = [
        tid
        for tid, timestamp in _CSRF_TOKENS.items()
        if current_time - timestamp > _CSRF_TOKEN_EXPIRY_SECONDS
    ]
    for tid in expired_csrf:
        _CSRF_TOKENS.pop(tid, None)

    # Enforce max limits (remove oldest if over limit)

    if len(_CSRF_TOKENS) > _MAX_CSRF_TOKENS:
        before = len(_CSRF_TOKENS)
        # Sort by timestamp and keep only the newest MAX_CSRF_TOKENS
        sorted_csrf = sorted(_CSRF_TOKENS.items(), key=lambda x: x[1], reverse=True)
        _CSRF_TOKENS.clear()
        _CSRF_TOKENS.update(dict(sorted_csrf[:_MAX_CSRF_TOKENS]))
        csrf_pruned = before - len(_CSRF_TOKENS)
        logger.warning(
            f"CSRF token storage limit reached, pruned {csrf_pruned} expired entries"
        )

    return expired_csrf
