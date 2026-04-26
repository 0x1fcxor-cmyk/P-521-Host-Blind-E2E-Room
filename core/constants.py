"""
Core constants for the P-521 Host-Blind E2E Room application
"""

from pathlib import Path
from rich.console import Console

# Application metadata
APP_NAME = "P-521 Host-Blind E2E Room"
PROTOCOL_VERSION = "P521-HOST-BLIND-E2E-V1"

# Directory paths
APP_DIR = Path.home() / ".p521_host_blind_room"
IDENTITY_FILE = APP_DIR / "identity_p521_private.pem"
PUBLIC_FILE = APP_DIR / "identity_p521_public.pem"
STORAGE_SALT_FILE = APP_DIR / "storage_salt.bin"
SETTINGS_FILE = APP_DIR / "settings.enc"
TRUST_FILE = APP_DIR / "trusted_contacts.enc"
LOG_DIR = APP_DIR / "logs"
DOWNLOAD_DIR = APP_DIR / "downloads"
CONFIG_FILE = APP_DIR / "config.json"

# Network configuration
DEFAULT_PORT_MIN = 20000
DEFAULT_PORT_MAX = 50000
MAX_WS_MESSAGE = 32 * 1024 * 1024  # 32 MB
FILE_CHUNK_SIZE = 512 * 1024  # 512 KB
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Cryptographic AAD (Additional Authenticated Data)
STORAGE_AAD = b"P521-HOST-BLIND-STORAGE-V1"
OVERLAY_AAD = b"P521-HOST-BLIND-E2E-OVERLAY-V1"

# Console for rich output
console = Console()

__all__ = [
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
    'CONFIG_FILE',
    'DEFAULT_PORT_MIN',
    'DEFAULT_PORT_MAX',
    'MAX_WS_MESSAGE',
    'FILE_CHUNK_SIZE',
    'DEFAULT_MAX_FILE_SIZE',
    'STORAGE_AAD',
    'OVERLAY_AAD',
    'console'
]
