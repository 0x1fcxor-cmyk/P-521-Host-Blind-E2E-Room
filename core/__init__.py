"""
Core module - Shared constants and utilities
"""

from .constants import *
from .key_schedule import hkdf_derive, derive_storage_key, get_or_create_storage_salt

__all__ = [
    # Constants
    'APP_NAME',
    'PROTOCOL_VERSION',
    'APP_DIR',
    'IDENTITY_FILE',
    'PUBLIC_FILE',
    'STORAGE_SALT_FILE',
    'SETTINGS_FILE',
    'TRUST_FILE',
    'LOG_DIR',
    'DOWNLOAD_DIR',
    'DEFAULT_PORT_MIN',
    'DEFAULT_PORT_MAX',
    'MAX_WS_MESSAGE',
    'STORAGE_AAD',
    'OVERLAY_AAD',
    # Key schedule
    'hkdf_derive',
    'derive_storage_key',
    'get_or_create_storage_salt'
]
