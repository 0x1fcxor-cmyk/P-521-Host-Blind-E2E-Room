"""
Key schedule module - HKDF-based key derivation with labeled contexts
"""

import os
import logging
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import STORAGE_SALT_FILE

logger = logging.getLogger(__name__)

__all__ = [
    'hkdf_derive',
    'derive_storage_key',
    'get_or_create_storage_salt'
]


class KeyDerivationError(Exception):
    """Base exception for key derivation errors"""
    pass


class InvalidInputError(KeyDerivationError):
    """Raised when input parameters are invalid"""
    pass


def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a key using HKDF-SHA512 with labeled context.
    
    Args:
        ikm: Input key material (must not be empty)
        salt: Salt value (use empty bytes if none)
        info: Context label (e.g., b"0x1FC/message/aead/v1")
        length: Output key length in bytes (1-64)
    
    Returns:
        Derived key
    
    Raises:
        InvalidInputError: If input parameters are invalid
        KeyDerivationError: If key derivation fails
    """
    if not ikm:
        raise InvalidInputError("Input key material cannot be empty")
    
    if length < 1 or length > 64:
        raise InvalidInputError("Length must be between 1 and 64 bytes")
    
    if not isinstance(ikm, bytes) or not isinstance(salt, bytes) or not isinstance(info, bytes):
        raise InvalidInputError("All inputs must be bytes")
    
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)
    except Exception as e:
        logger.error(f"HKDF derivation failed: {e}")
        raise KeyDerivationError(f"Failed to derive key: {e}") from e


def derive_storage_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive storage key from password using Argon2id (with PBKDF2 fallback).
    
    Args:
        password: User password (bytes, must be at least 8 characters)
        salt: Salt for key derivation (bytes, must be at least 16 bytes)
    
    Returns:
        Derived storage key (32 bytes)
    
    Raises:
        InvalidInputError: If input parameters are invalid
        KeyDerivationError: If key derivation fails
    """
    if not password or len(password) < 8:
        raise InvalidInputError("Password must be at least 8 characters")
    
    if not salt or len(salt) < 16:
        raise InvalidInputError("Salt must be at least 16 bytes")
    
    # Use Argon2id for proper password hardening
    try:
        from argon2.low_level import hash_secret_raw, Type
        # Argon2id parameters for key derivation
        time_cost = 3
        memory_cost = 262144  # 256 MB
        parallelism = 4
        hash_len = 32
        
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Derive key using Argon2id
        derived = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID
        )
        logger.info("Using Argon2id for key derivation")
        return derived
    except ImportError:
        logger.warning("Argon2 not available, falling back to PBKDF2")
        # Fallback to PBKDF2 if argon2 not available
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=600000,  # Higher iterations for SHA512
            )
            return kdf.derive(password)
        except Exception as e:
            logger.error(f"PBKDF2 derivation failed: {e}")
            raise KeyDerivationError(f"Failed to derive storage key: {e}") from e
    except Exception as e:
        logger.error(f"Argon2 derivation failed: {e}")
        raise KeyDerivationError(f"Failed to derive storage key: {e}") from e


def get_or_create_storage_salt() -> bytes:
    """
    Get existing storage salt or create a new one.
    
    Returns:
        32-byte salt for storage key derivation
    
    Raises:
        KeyDerivationError: If salt creation or retrieval fails
    """
    try:
        STORAGE_SALT_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        if STORAGE_SALT_FILE.exists():
            salt = STORAGE_SALT_FILE.read_bytes()
            if len(salt) != 32:
                logger.warning(f"Invalid salt length {len(salt)}, regenerating")
                salt = os.urandom(32)
                STORAGE_SALT_FILE.write_bytes(salt)
            return salt

        salt = os.urandom(32)
        STORAGE_SALT_FILE.write_bytes(salt)
        logger.info("Created new storage salt")
        return salt
    except Exception as e:
        logger.error(f"Failed to get or create storage salt: {e}")
        raise KeyDerivationError(f"Failed to get or create storage salt: {e}") from e
