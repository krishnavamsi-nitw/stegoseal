"""Authenticated encryption helpers used by StegoSeal."""

import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits, the recommended AES-GCM nonce size
TAG_SIZE = 16
ENVELOPE_MAGIC = b"SSG1"


def generate_key() -> str:
    """Return a fresh random AES-256 key encoded as URL-safe Base64."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE)).decode("ascii")


def decode_key(key_text: str) -> bytes:
    """Validate and decode a URL-safe Base64 AES-256 key."""
    try:
        key = base64.b64decode(key_text.strip().encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("The key must be the generated URL-safe Base64 key.") from exc
    if len(key) != KEY_SIZE:
        raise ValueError("The decoded key must be exactly 32 bytes (AES-256).")
    return key


def encrypt_message(message: str, key_text: str) -> bytes:
    """Encrypt UTF-8 text and return a versioned nonce+ciphertext envelope."""
    if not message:
        raise ValueError("Enter a message before encrypting.")
    key = decode_key(key_text)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, message.encode("utf-8"), ENVELOPE_MAGIC)
    return ENVELOPE_MAGIC + nonce + ciphertext_and_tag


def decrypt_message(envelope: bytes, key_text: str) -> str:
    """Authenticate and decrypt an envelope; reject malformed/tampered bytes."""
    minimum_size = len(ENVELOPE_MAGIC) + NONCE_SIZE + TAG_SIZE
    if len(envelope) < minimum_size or not envelope.startswith(ENVELOPE_MAGIC):
        raise ValueError("The hidden payload is malformed or uses an unsupported version.")
    key = decode_key(key_text)
    nonce_start = len(ENVELOPE_MAGIC)
    nonce = envelope[nonce_start : nonce_start + NONCE_SIZE]
    ciphertext_and_tag = envelope[nonce_start + NONCE_SIZE :]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext_and_tag, ENVELOPE_MAGIC)
        return plaintext.decode("utf-8")
    except Exception as exc:
        # Do not reveal whether the key, ciphertext, or authentication tag was wrong.
        raise ValueError("Authentication failed: wrong key or the hidden data was changed.") from exc
