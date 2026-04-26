"""
Trust module - Contact trust management
"""

import time
import logging
from typing import Optional
from core.constants import SETTINGS_FILE, TRUST_FILE, DEFAULT_MAX_FILE_SIZE
from storage.vault import StorageVault, EncryptionError, DecryptionError

logger = logging.getLogger(__name__)

__all__ = [
    'normalize_fp',
    'short_fp',
    'default_settings',
    'default_trust',
    'vault',
    'get_settings',
    'save_settings',
    'load_trust',
    'save_trust',
    'trust_contact',
    'trusted_name'
]


class TrustError(Exception):
    """Base exception for trust management errors"""
    pass


def normalize_fp(fp: str) -> str:
    """
    Normalize fingerprint by removing separators and spaces
    
    Args:
        fp: Fingerprint string (may contain colons, dashes, spaces)
    
    Returns:
        Normalized uppercase fingerprint without separators
    
    Raises:
        ValueError: If fp is empty or invalid
    """
    if not fp:
        raise ValueError("Fingerprint cannot be empty")
    
    normalized = fp.replace(":", "").replace("-", "").replace(" ", "").strip().upper()
    
    if not normalized or len(normalized) != 64:
        raise ValueError("Invalid fingerprint length (expected 64 hex characters)")
    
    try:
        int(normalized, 16)  # Validate hex
    except ValueError:
        raise ValueError("Fingerprint contains invalid hex characters")
    
    return normalized


def short_fp(fp: str) -> str:
    """
    Get short fingerprint (first 16 chars)
    
    Args:
        fp: Fingerprint string
    
    Returns:
        Short fingerprint (first 16 characters)
    """
    return normalize_fp(fp)[:16]


def default_settings() -> dict:
    """
    Default user settings
    
    Returns:
        Dictionary with default settings
    """
    return {
        "display_name": "P-521 User",
        "max_file_size": DEFAULT_MAX_FILE_SIZE,
    }


def default_trust() -> dict:
    """
    Default trust store structure
    
    Returns:
        Dictionary with default trust structure
    """
    return {
        "contacts_by_fingerprint": {},
        "nickname_index": {},
    }


def vault(identity) -> StorageVault:
    """
    Get StorageVault instance for identity
    
    Args:
        identity: Identity object with storage_key
    
    Returns:
        StorageVault instance
    
    Raises:
        ValueError: If identity has no storage_key
    """
    if not hasattr(identity, 'storage_key') or not identity.storage_key:
        raise ValueError("Identity has no storage_key")
    
    return StorageVault(identity.storage_key)


def get_settings(identity) -> dict:
    """
    Load user settings from encrypted storage
    
    Args:
        identity: Identity object
    
    Returns:
        Settings dictionary (defaults if file doesn't exist)
    
    Raises:
        TrustError: If settings cannot be loaded
    """
    try:
        return vault(identity).decrypt_json_file(SETTINGS_FILE, default_settings())
    except DecryptionError as e:
        logger.warning(f"Failed to decrypt settings (using defaults): {e}")
        return default_settings()
    except Exception as e:
        logger.error(f"Failed to load settings: {e}")
        raise TrustError(f"Failed to load settings: {e}") from e


def save_settings(identity, settings: dict) -> None:
    """
    Save user settings to encrypted storage
    
    Args:
        identity: Identity object
        settings: Settings dictionary to save
    
    Raises:
        ValueError: If settings is empty
        TrustError: If settings cannot be saved
    """
    if not settings:
        raise ValueError("Settings cannot be empty")
    
    try:
        vault(identity).encrypt_json_file(SETTINGS_FILE, settings)
        logger.info("Settings saved successfully")
    except EncryptionError as e:
        logger.error(f"Failed to encrypt settings: {e}")
        raise TrustError(f"Failed to save settings: {e}") from e
    except Exception as e:
        logger.error(f"Failed to save settings: {e}")
        raise TrustError(f"Failed to save settings: {e}") from e


def load_trust(identity) -> dict:
    """
    Load trust store from encrypted storage
    
    Args:
        identity: Identity object
    
    Returns:
        Trust store dictionary (defaults if file doesn't exist)
    
    Raises:
        TrustError: If trust store cannot be loaded
    """
    try:
        return vault(identity).decrypt_json_file(TRUST_FILE, default_trust())
    except DecryptionError as e:
        logger.warning(f"Failed to decrypt trust store (using defaults): {e}")
        return default_trust()
    except Exception as e:
        logger.error(f"Failed to load trust store: {e}")
        raise TrustError(f"Failed to load trust store: {e}") from e


def save_trust(identity, trust: dict) -> None:
    """
    Save trust store to encrypted storage
    
    Args:
        identity: Identity object
        trust: Trust store dictionary to save
    
    Raises:
        ValueError: If trust is empty or invalid
        TrustError: If trust store cannot be saved
    """
    if not trust:
        raise ValueError("Trust store cannot be empty")
    
    if "contacts_by_fingerprint" not in trust or "nickname_index" not in trust:
        raise ValueError("Invalid trust store structure")
    
    try:
        vault(identity).encrypt_json_file(TRUST_FILE, trust)
        logger.info(f"Trust store saved with {len(trust['contacts_by_fingerprint'])} contacts")
    except EncryptionError as e:
        logger.error(f"Failed to encrypt trust store: {e}")
        raise TrustError(f"Failed to save trust store: {e}") from e
    except Exception as e:
        logger.error(f"Failed to save trust store: {e}")
        raise TrustError(f"Failed to save trust store: {e}") from e


def trust_contact(identity, fp: str, name: str) -> None:
    """
    Add a contact to the trust store
    
    Args:
        identity: Identity object
        fp: Fingerprint of the contact
        name: Display name for the contact
    
    Raises:
        ValueError: If fp or name is invalid
        TrustError: If contact cannot be added
    """
    if not fp:
        raise ValueError("Fingerprint cannot be empty")
    
    if not name or not name.strip():
        raise ValueError("Name cannot be empty")
    
    try:
        nfp = normalize_fp(fp)
        trust = load_trust(identity)
        
        trust["contacts_by_fingerprint"][nfp] = {
            "fingerprint": nfp,
            "name": name.strip(),
            "trusted_at": int(time.time()),
        }
        
        trust["nickname_index"][name.strip().lower()] = nfp
        
        save_trust(identity, trust)
        logger.info(f"Added trusted contact: {name} ({nfp[:16]}...)")
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"Failed to trust contact: {e}")
        raise TrustError(f"Failed to trust contact: {e}") from e


def trusted_name(identity, fp: str) -> Optional[str]:
    """
    Get trusted name for a fingerprint
    
    Args:
        identity: Identity object
        fp: Fingerprint to look up
    
    Returns:
        Trusted name if found, None otherwise
    """
    try:
        nfp = normalize_fp(fp)
        trust = load_trust(identity)
        
        if nfp in trust["contacts_by_fingerprint"]:
            return trust["contacts_by_fingerprint"][nfp]["name"]
        
        return None
    except ValueError:
        logger.warning(f"Invalid fingerprint format: {fp}")
        return None
    except Exception as e:
        logger.error(f"Failed to get trusted name: {e}")
        return None
