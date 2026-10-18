import hashlib
import os
import hmac


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100_000
    )
    return salt.hex() + ":" + password_hash.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored salted hash."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100_000
        )
        return hmac.compare_digest(actual_hash, expected_hash)
    except (ValueError, TypeError):
        return False


def register_user(email: str, password: str) -> dict:
    """Represent a basic user registration endpoint."""
    if not email or "@" not in email:
        return {"success": False, "message": "Invalid email address"}

    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters"}

    return {
        "success": True,
        "email": email,
        "password_hash": hash_password(password),
        "message": "User registered successfully",
    }
