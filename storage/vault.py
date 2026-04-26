"""
StorageVault - Encrypted file storage using AES-256-GCM
"""

import base64
import json
import os
import logging
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

STORAGE_AAD = b"0x1FC-STORAGE-AAD-V1"

logger = logging.getLogger(__name__)

__all__ = ['StorageVault', 'STORAGE_AAD']


class StorageVaultError(Exception):
    """Base exception for StorageVault errors"""
    pass


class EncryptionError(StorageVaultError):
    """Raised when encryption fails"""
    pass


class DecryptionError(StorageVaultError):
    """Raised when decryption fails"""
    pass


class StorageVault:
    """Encrypted storage vault for sensitive data"""
    
    def __init__(self, key: bytes):
        if not key or len(key) < 32:
            raise ValueError("Key must be at least 32 bytes")
        self.key = key

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt bytes using AES-256-GCM"""
        if not data:
            raise ValueError("Data cannot be empty")
        
        try:
            nonce = os.urandom(12)
            ciphertext = AESGCM(self.key).encrypt(nonce, data, STORAGE_AAD)

            return json.dumps({
                "v": 1,
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            }).encode("utf-8")
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt data: {e}") from e

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt bytes using AES-256-GCM"""
        if not data:
            raise ValueError("Data cannot be empty")
        
        try:
            payload = json.loads(data.decode("utf-8"))
            
            if "nonce" not in payload or "ciphertext" not in payload:
                raise DecryptionError("Invalid payload format")
            
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            
            return AESGCM(self.key).decrypt(nonce, ciphertext, STORAGE_AAD)
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Invalid payload format: {e}")
            raise DecryptionError(f"Invalid payload format: {e}") from e
        except InvalidTag as e:
            logger.error(f"Decryption authentication failed: {e}")
            raise DecryptionError("Authentication failed - data may be corrupted") from e
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt data: {e}") from e

    def encrypt_json(self, obj: dict) -> bytes:
        """Encrypt JSON object to bytes"""
        if not obj:
            raise ValueError("Object cannot be empty")
        
        try:
            raw = json.dumps(obj, indent=2).encode("utf-8")
            return self.encrypt_bytes(raw)
        except Exception as e:
            logger.error(f"Failed to encrypt JSON: {e}")
            raise EncryptionError(f"Failed to encrypt JSON: {e}") from e

    def decrypt_json(self, data: bytes) -> dict:
        """Decrypt bytes to JSON object"""
        if not data:
            raise ValueError("Data cannot be empty")
        
        try:
            raw = self.decrypt_bytes(data)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to parse JSON: {e}")
            raise DecryptionError(f"Failed to parse JSON: {e}") from e
        except Exception as e:
            logger.error(f"Failed to decrypt JSON: {e}")
            raise DecryptionError(f"Failed to decrypt JSON: {e}") from e

    def encrypt_file(self, input_path: Path, output_path: Path) -> None:
        """Encrypt a file"""
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            raw = input_path.read_bytes()
            encrypted = self.encrypt_bytes(raw)
            output_path.write_bytes(encrypted)
        except Exception as e:
            logger.error(f"Failed to encrypt file {input_path}: {e}")
            raise EncryptionError(f"Failed to encrypt file: {e}") from e

    def decrypt_file(self, input_path: Path, output_path: Path) -> None:
        """Decrypt a file"""
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            raw = input_path.read_bytes()
            decrypted = self.decrypt_bytes(raw)
            output_path.write_bytes(decrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt file {input_path}: {e}")
            raise DecryptionError(f"Failed to decrypt file: {e}") from e

    def encrypt_json_file(self, path: Path, obj: dict) -> None:
        """Encrypt and write JSON object to file"""
        if not obj:
            raise ValueError("Object cannot be empty")
        
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(obj, indent=2).encode("utf-8")
            encrypted = self.encrypt_bytes(raw)
            
            # Write to temporary file first, then rename for atomicity
            temp_path = path.with_suffix('.tmp')
            temp_path.write_bytes(encrypted)
            temp_path.replace(path)
            
        except Exception as e:
            logger.error(f"Failed to encrypt JSON file {path}: {e}")
            raise EncryptionError(f"Failed to encrypt file: {e}") from e

    def decrypt_json_file(self, path: Path, default: dict = None) -> dict:
        """Decrypt and read JSON object from file"""
        if default is None:
            default = {}
        
        if not path.exists():
            logger.debug(f"File not found: {path}, returning default")
            return default

        try:
            raw = path.read_bytes()
            decrypted = self.decrypt_bytes(raw)
            return json.loads(decrypted.decode("utf-8"))
        except DecryptionError as e:
            logger.error(f"Failed to decrypt JSON file {path}: {e}")
            return default
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Failed to parse JSON from {path}: {e}")
            return default
        except Exception as e:
            logger.error(f"Unexpected error reading {path}: {e}")
            return default

    def encrypted_log_line(self, path: Path, entry: dict) -> None:
        """Append an encrypted log line to file"""
        if not entry:
            raise ValueError("Log entry cannot be empty")
        
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(entry, separators=(",", ":")).encode("utf-8")
            line = self.encrypt_bytes(raw)

            with path.open("ab") as f:
                f.write(base64.b64encode(line) + b"\n")
        except Exception as e:
            logger.error(f"Failed to write encrypted log line to {path}: {e}")
            raise EncryptionError(f"Failed to write log line: {e}") from e
