"""
Unit tests for storage.vault module
"""

import pytest
import tempfile
from pathlib import Path

from storage.vault import (
    StorageVault,
    EncryptionError,
    DecryptionError,
    StorageVaultError
)
from identity.keys import generate_identity


class TestStorageVault:
    """Tests for StorageVault encryption/decryption"""

    def test_encrypt_decrypt_bytes(self):
        """Test encrypting and decrypting bytes"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            data = b"test_data_to_encrypt"
            encrypted = vault.encrypt_bytes(data)
            decrypted = vault.decrypt_bytes(encrypted)
            
            assert decrypted == data
            assert encrypted != data

    def test_encrypt_bytes_empty(self):
        """Test encrypting empty data raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            with pytest.raises(ValueError, match="Data cannot be empty"):
                vault.encrypt_bytes(b"")

    def test_encrypt_decrypt_json(self):
        """Test encrypting and decrypting JSON"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            data = {"key": "value", "number": 42}
            encrypted = vault.encrypt_json(data)
            decrypted = vault.decrypt_json(encrypted)
            
            assert decrypted == data

    def test_decrypt_bytes_invalid(self):
        """Test decrypting invalid data raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            with pytest.raises(DecryptionError):
                vault.decrypt_bytes(b"invalid_encrypted_data")

    def test_encrypt_decrypt_file(self):
        """Test encrypting and decrypting a file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            # Create test file
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")
            
            encrypted_file = Path(tmpdir) / "test.enc"
            vault.encrypt_file(test_file, encrypted_file)
            
            decrypted_file = Path(tmpdir) / "test_decrypted.txt"
            vault.decrypt_file(encrypted_file, decrypted_file)
            
            assert decrypted_file.read_text() == "test content"

    def test_decrypt_json_file_default(self):
        """Test decrypting JSON file with default on error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            default = {"default": "value"}
            result = vault.decrypt_json_file(Path(tmpdir) / "nonexistent.json", default=default)
            
            assert result == default

    def test_encrypted_log_line(self):
        """Test encrypted logging"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            vault = StorageVault(identity.storage_key)
            
            log_file = Path(tmpdir) / "audit.log"
            entry = {"event": "test", "data": "value"}
            
            vault.encrypted_log_line(log_file, entry)
            
            assert log_file.exists()
            assert log_file.stat().st_size > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
