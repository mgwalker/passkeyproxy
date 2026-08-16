import asyncio

from aiohttp import web

from lib.challenges import (
    clear_expired_challenges,
)
from lib.csrf_tokens import (
    clear_expired_csrf_tokens,
)
from lib.logger import logger
from lib.rate_limit import clear_expired_rate_limits

CLEANUP_INTERVAL_SECONDS = 30  # Run cleanup every 30 seconds


def cleanup_expired_items():
    """Remove expired challenges, CSRF tokens, and rate limit entries"""

    # Cleanup expired challenges
    expired_challenges = clear_expired_challenges()
    expired_csrf = clear_expired_csrf_tokens()
    rate_limits_cleaned = clear_expired_rate_limits()

    # DEBUG logging for regular cleanup (only if something was cleaned)
    total_cleaned = len(expired_challenges) + len(expired_csrf) + rate_limits_cleaned
    if total_cleaned > 0:
        logger.debug(
            f"Cleanup: removed {len(expired_challenges)} challenges, {len(expired_csrf)} CSRF tokens, {rate_limits_cleaned} rate limit entries"  # noqa: E501
        )


async def cleanup_background_task(app: web.Application):
    """Background task to cleanup expired items"""

    async def cleanup_loop():
        while True:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
                cleanup_expired_items()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    task = asyncio.create_task(cleanup_loop())
    yield
    task.cancel()
    try:  # noqa: SIM105
        await task
    except asyncio.CancelledError:
        pass
