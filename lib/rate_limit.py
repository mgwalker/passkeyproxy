import time

from aiohttp import web

from lib.logger import logger
from lib.util import get_client_ip

_RATE_LIMITS: dict[
    str, dict[str, dict]
] = {}  # ip -> {endpoint -> {count, window_start}}


def rate_limit(max_requests: int, window_seconds: int = 60):
    """
    Rate limiting decorator for route handlers
    Limits requests per IP address per endpoint
    """

    def decorator(handler):
        async def wrapper(request: web.Request) -> web.Response:
            client_ip = get_client_ip(request)
            endpoint = request.path
            current_time = time.time()

            # Initialize rate limit tracking for this IP
            if client_ip not in _RATE_LIMITS:
                _RATE_LIMITS[client_ip] = {}

            # Initialize tracking for this endpoint
            if endpoint not in _RATE_LIMITS[client_ip]:
                _RATE_LIMITS[client_ip][endpoint] = {
                    "count": 0,
                    "window_start": current_time,
                }

            endpoint_data = _RATE_LIMITS[client_ip][endpoint]

            # Check if we're in a new window
            if current_time - endpoint_data["window_start"] > window_seconds:
                # Reset window
                endpoint_data["count"] = 0
                endpoint_data["window_start"] = current_time

            # Check rate limit
            if endpoint_data["count"] >= max_requests:
                # Rate limit exceeded
                retry_after = (
                    int(window_seconds - (current_time - endpoint_data["window_start"]))
                    + 1
                )
                logger.warning(
                    f"Rate limit exceeded from {client_ip} for {endpoint} (retry after {retry_after}s)"  # noqa: E501
                )
                response = web.Response(
                    text="Too many requests. Please try again later.", status=429
                )
                response.headers["Retry-After"] = str(retry_after)
                return response

            # Increment counter
            endpoint_data["count"] += 1

            # Call the actual handler
            return await handler(request)

        return wrapper

    return decorator


def clear_expired_rate_limits():
    rate_limits_cleaned = 0
    current_time = time.time()

    for ip in list(_RATE_LIMITS.keys()):
        for endpoint in list(_RATE_LIMITS[ip].keys()):
            window_start = _RATE_LIMITS[ip][endpoint].get("window_start", 0)
            if current_time - window_start > 120:
                _RATE_LIMITS[ip].pop(endpoint, None)
                rate_limits_cleaned += 1
        # Remove IP if no endpoints remain
        if not _RATE_LIMITS[ip]:
            _RATE_LIMITS.pop(ip, None)
    return rate_limits_cleaned
