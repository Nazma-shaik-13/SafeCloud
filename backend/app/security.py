import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .config import SESSION_HOURS

_ph = PasswordHasher()                        # Argon2id with safe defaults
DUMMY_HASH = _ph.hash("not-a-real-password")  # verified when the email is unknown, so timing doesn't reveal it


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(conn, user_id) -> str:
    token = secrets.token_urlsafe(32)         # random; goes in the cookie only
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    conn.execute("INSERT INTO sessions(id_hash, user_id, expires_at) VALUES (%s,%s,%s)",
                 (_digest(token), user_id, expires))
    return token


def user_from_token(conn, token: str):
    """Valid only if session not revoked/expired AND the user is still active.
    Looked up in the DB on every request, so disabling a user works immediately."""
    return conn.execute(
        """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.id_hash=%s AND s.revoked_at IS NULL AND s.expires_at > now() AND u.is_active""",
        (_digest(token),)).fetchone()


def revoke_session(conn, token: str):
    conn.execute("UPDATE sessions SET revoked_at=now() WHERE id_hash=%s", (_digest(token),))
