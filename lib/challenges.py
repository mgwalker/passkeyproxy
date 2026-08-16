import time

from lib.logger import logger

_CHALLENGE_EXPIRY_SECONDS = 60  # WebAuthn challenges expire after 60 seconds
_MAX_CHALLENGES = 1000  # Maximum number of challenges in memory

_CHALLENGES: dict[
    str, dict
] = {}  # challenge_id -> {challenge, username, timestamp, type}


def set_challenge(challenge_id, challenge):
    _CHALLENGES[challenge_id] = challenge


def get_challenge(challenge_id):
    return _CHALLENGES.get(challenge_id)


def validate_challenge(challenge_id, max_age: int = _CHALLENGE_EXPIRY_SECONDS) -> bool:
    """Validate that a challenge timestamp is not expired"""
    data = get_challenge(challenge_id)

    if data:
        timestamp = data.get("timestamp", 0)

        if (time.time() - timestamp) > max_age:
            _CHALLENGES.pop(challenge_id, None)
            return False

        return True

    return False


def remove_challenge(challenge_id):
    _CHALLENGES.pop(challenge_id, None)


def clear_expired_challenges():
    # Cleanup expired challenges
    current_time = time.time()
    expired_challenges = [
        cid
        for cid, data in _CHALLENGES.items()
        if current_time - data.get("timestamp", 0) > _CHALLENGE_EXPIRY_SECONDS
    ]
    for cid in expired_challenges:
        _CHALLENGES.pop(cid, None)

    if len(_CHALLENGES) > _MAX_CHALLENGES:
        before = len(_CHALLENGES)
        # Sort by timestamp and keep only the newest MAX_CHALLENGES
        sorted_challenges = sorted(
            _CHALLENGES.items(), key=lambda x: x[1].get("timestamp", 0), reverse=True
        )
        _CHALLENGES.clear()
        _CHALLENGES.update(dict(sorted_challenges[:_MAX_CHALLENGES]))
        challenges_pruned = before - len(_CHALLENGES)
        logger.warning(
            f"Challenge storage limit reached, pruned {challenges_pruned} expired entries"  # noqa: E501
        )

    return expired_challenges
