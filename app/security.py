import re
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

# Argon2id is the library default (type=argon2.low_level.Type.ID).
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def hash_password(plain_password: str) -> str:
    return _hasher.hash(plain_password)


def verify_password(stored_hash: str, plain_password: str) -> bool:
    try:
        return _hasher.verify(stored_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def validate_username(username: str) -> str | None:
    if not USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, numbers, or underscore only."
    return None


def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "Password must contain at least one letter and one number."
    return None


# --- Very small in-memory login throttle (per-process demo only) ---
# For production, back this with Redis or the database so it survives
# restarts and works across multiple app instances.
_FAILED_ATTEMPTS: dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def is_locked_out(username: str) -> bool:
    attempts = _FAILED_ATTEMPTS.get(username, [])
    cutoff = time.time() - LOCKOUT_SECONDS
    attempts = [t for t in attempts if t > cutoff]
    _FAILED_ATTEMPTS[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def record_failed_attempt(username: str) -> None:
    _FAILED_ATTEMPTS.setdefault(username, []).append(time.time())


def clear_failed_attempts(username: str) -> None:
    _FAILED_ATTEMPTS.pop(username, None)
