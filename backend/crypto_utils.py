# -----------------------------------------------------------------------
# Credential Encryption (AES-256 via Fernet)
# Every client's Shopify credentials (access + refresh tokens) pass through here.
# The database NEVER sees the raw secret - only this encrypted form.
# -----------------------------------------------------------------------
import os
from cryptography.fernet import Fernet

def _get_fernet():
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.strip().encode())

def encrypt_key(raw_secret: str) -> str:
    """Turn a plain Shopify token into an encrypted string safe to store."""
    if not raw_secret:
        return ""
    return _get_fernet().encrypt(raw_secret.strip().encode()).decode()

def decrypt_key(encrypted_secret: str) -> str:
    """Turn a stored encrypted ciphertext back into the real Shopify token, in memory only."""
    if not encrypted_secret:
        return ""
    return _get_fernet().decrypt(encrypted_secret.encode()).decode()
