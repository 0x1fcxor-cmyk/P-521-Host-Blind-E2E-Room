"""
Identity keys module - P-521 key generation and management
"""

import hashlib
import getpass
import logging
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature, InvalidTag

from core.constants import (
    IDENTITY_FILE, PUBLIC_FILE, SETTINGS_FILE, TRUST_FILE,
    STORAGE_AAD, console
)
from core.key_schedule import derive_storage_key, get_or_create_storage_salt, KeyDerivationError
from storage.vault import StorageVault, DecryptionError

logger = logging.getLogger(__name__)

__all__ = [
    'Identity',
    'generate_identity',
    'load_identity',
    'load_identity_from_file',
    'fingerprint_from_der',
    'public_to_pem',
    'public_to_der',
    'private_to_encrypted_pem',
    'load_private_pem'
]


class IdentityError(Exception):
    """Base exception for identity errors"""
    pass


class InvalidPasswordError(IdentityError):
    """Raised when password is invalid"""
    pass


class CorruptedIdentityError(IdentityError):
    """Raised when identity files are corrupted"""
    pass


@dataclass
class Identity:
    """User identity with P-521 signing key"""
    private_key: ec.EllipticCurvePrivateKey
    public_pem: bytes
    public_der: bytes
    fingerprint: str
    storage_key: bytes
    display_name: str


def fingerprint_from_der(public_der: bytes) -> str:
    """
    Calculate fingerprint from DER-encoded public key
    
    Args:
        public_der: DER-encoded public key bytes
    
    Returns:
        SHA-256 fingerprint formatted with colons
    
    Raises:
        ValueError: If public_der is empty or invalid
    """
    if not public_der:
        raise ValueError("Public key DER cannot be empty")
    
    try:
        digest = hashlib.sha256(public_der).hexdigest().upper()
        return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    except Exception as e:
        logger.error(f"Failed to calculate fingerprint: {e}")
        raise ValueError(f"Failed to calculate fingerprint: {e}") from e


def public_to_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Convert public key to PEM format
    
    Args:
        public_key: Elliptic curve public key
    
    Returns:
        PEM-encoded public key bytes
    
    Raises:
        ValueError: If conversion fails
    """
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        logger.error(f"Failed to convert public key to PEM: {e}")
        raise ValueError(f"Failed to convert public key to PEM: {e}") from e


def public_to_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Convert public key to DER format
    
    Args:
        public_key: Elliptic curve public key
    
    Returns:
        DER-encoded public key bytes
    
    Raises:
        ValueError: If conversion fails
    """
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        logger.error(f"Failed to convert public key to DER: {e}")
        raise ValueError(f"Failed to convert public key to DER: {e}") from e


def private_to_encrypted_pem(private_key: ec.EllipticCurvePrivateKey, password: str) -> bytes:
    """
    Encrypt private key with password using PBKDF2-HMAC-SHA256
    
    Args:
        private_key: Elliptic curve private key
        password: Password for encryption (must not be empty)
    
    Returns:
        PEM-encoded encrypted private key bytes
    
    Raises:
        ValueError: If password is empty or encryption fails
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    try:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    except Exception as e:
        logger.error(f"Failed to encrypt private key: {e}")
        raise ValueError(f"Failed to encrypt private key: {e}") from e


def load_private_pem(data: bytes, password: str) -> ec.EllipticCurvePrivateKey:
    """
    Load encrypted private key from PEM
    
    Args:
        data: PEM-encoded private key bytes
        password: Password for decryption
    
    Returns:
        Elliptic curve private key
    
    Raises:
        InvalidPasswordError: If password is wrong
        CorruptedIdentityError: If key file is corrupted
    """
    if not data:
        raise CorruptedIdentityError("Private key data is empty")
    
    if not password:
        raise InvalidPasswordError("Password cannot be empty")
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode("utf-8")
    
    try:
        return serialization.load_pem_private_key(data, password=password)
    except ValueError as e:
        logger.error(f"Invalid password or corrupted key: {e}")
        raise InvalidPasswordError("Wrong password or corrupted identity file") from e
    except Exception as e:
        logger.error(f"Failed to load private key: {e}")
        raise CorruptedIdentityError(f"Failed to load private key: {e}") from e


def generate_identity(display_name: str = "P-521 User", password: str = None) -> Identity:
    """
    Generate a new P-521 identity
    
    Args:
        display_name: Display name for the identity
        password: Password for encryption (will prompt if None)
    
    Returns:
        Identity object with generated keys
    
    Raises:
        IdentityError: If identity generation fails
    """
    if not display_name:
        display_name = "P-521 User"
    
    if password is None:
        password = getpass.getpass("Create identity password: ").encode("utf-8")
    
    if isinstance(password, str):
        password = password.encode("utf-8")
    
    if len(password) < 8:
        raise InvalidPasswordError("Password must be at least 8 characters")
    
    try:
        private_key = ec.generate_private_key(ec.SECP521R1())
        public_key = private_key.public_key()
        
        public_pem = public_to_pem(public_key)
        public_der = public_to_der(public_key)
        fp = fingerprint_from_der(public_der)
        
        storage_key = derive_storage_key(password, get_or_create_storage_salt())
        
        logger.info(f"Generated new identity with fingerprint {fp[:16]}...")
        
        return Identity(
            private_key=private_key,
            public_pem=public_pem,
            public_der=public_der,
            fingerprint=fp,
            storage_key=storage_key,
            display_name=display_name
        )
    except KeyDerivationError as e:
        logger.error(f"Failed to derive storage key: {e}")
        raise IdentityError(f"Failed to generate identity: {e}") from e
    except Exception as e:
        logger.error(f"Failed to generate identity: {e}")
        raise IdentityError(f"Failed to generate identity: {e}") from e


def load_identity_from_file(password: str) -> Optional[Identity]:
    """
    Load identity from file with password
    
    Args:
        password: Password for decryption
    
    Returns:
        Identity object if successful, None if file doesn't exist
    
    Raises:
        InvalidPasswordError: If password is wrong
        CorruptedIdentityError: If identity files are corrupted
        IdentityError: For other errors
    """
    if not IDENTITY_FILE.exists():
        logger.info("Identity file does not exist")
        return None

    if not password:
        raise InvalidPasswordError("Password cannot be empty")

    try:
        # Use PEM encryption
        data = IDENTITY_FILE.read_bytes()
        private_key = load_private_pem(data, password)
        
        public_key = private_key.public_key()
        public_pem = public_to_pem(public_key)
        public_der = public_to_der(public_key)

        fp = hashlib.sha256(public_der).hexdigest().upper()

        # Derive storage key
        storage_salt = get_or_create_storage_salt()
        storage_key = derive_storage_key(password.encode(), storage_salt)

        # Load display name from settings using StorageVault
        display_name = "User"
        if SETTINGS_FILE.exists():
            try:
                local_vault = StorageVault(storage_key)
                from .trust import default_settings
                settings = local_vault.decrypt_json_file(SETTINGS_FILE, default_settings())
                display_name = settings.get("display_name", "User")
            except DecryptionError as e:
                logger.warning(f"Failed to decrypt settings, using default: {e}")
            except Exception as e:
                logger.warning(f"Failed to load settings, using default: {e}")

        logger.info(f"Loaded identity with fingerprint {fp[:16]}...")
        
        return Identity(
            private_key=private_key,
            public_pem=public_pem,
            public_der=public_der,
            fingerprint=fp,
            storage_key=storage_key,
            display_name=display_name
        )
    except InvalidPasswordError:
        raise
    except CorruptedIdentityError:
        raise
    except Exception as e:
        logger.error(f"Failed to load identity: {e}")
        raise IdentityError(f"Failed to load identity: {type(e).__name__}: {e}") from e


def load_identity() -> Identity:
    """
    Load identity interactively (creates if doesn't exist)
    
    Returns:
        Identity object
    
    Raises:
        SystemExit: If user cancels after multiple failed attempts
    """
    from core.constants import APP_DIR
    from .trust import default_settings
    from rich.prompt import Confirm
    
    APP_DIR.mkdir(parents=True, exist_ok=True)

    if not IDENTITY_FILE.exists() or not PUBLIC_FILE.exists():
        logger.info("Identity files not found, generating new identity")
        return generate_identity()

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            password = getpass.getpass("Identity password: ").encode("utf-8")
            private_key = load_private_pem(IDENTITY_FILE.read_bytes(), password)
            public_key = private_key.public_key()
            public_pem = public_to_pem(public_key)
            public_der = public_to_der(public_key)
            fp = fingerprint_from_der(public_der)

            storage_key = derive_storage_key(password, get_or_create_storage_salt())
            settings = StorageVault(storage_key).decrypt_json_file(
                SETTINGS_FILE,
                default_settings(),
            )

            logger.info(f"Successfully loaded identity with fingerprint {fp[:16]}...")
            
            return Identity(
                private_key=private_key,
                public_pem=public_pem,
                public_der=public_der,
                fingerprint=fp,
                storage_key=storage_key,
                display_name=settings.get("display_name", "P-521 User"),
            )

        except InvalidPasswordError:
            remaining = max_attempts - attempt - 1
            console.print("[red]Wrong password or corrupted identity.[/red]")
            console.print()
            console.print("[yellow]Suggestions:[/yellow]")
            console.print("• Double-check your password (case-sensitive)")
            console.print("• If you recently changed your password, use the new one")
            console.print("• If identity files are corrupted, you may need to reset")
            
            if remaining > 0:
                if not Confirm.ask(f"Try again? ({remaining} attempts remaining)", default=True):
                    import sys
                    console.print("Identity load cancelled.")
                    sys.exit(1)
            else:
                console.print("[red]Maximum password attempts exceeded.[/red]")
                import sys
                sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error loading identity: {e}")
            console.print(f"[red]Error loading identity: {e}[/red]")
            import sys
            sys.exit(1)
