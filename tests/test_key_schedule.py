"""
Unit tests for core.key_schedule module
"""

import pytest
import os
from pathlib import Path
import tempfile

from core.key_schedule import (
    hkdf_derive,
    derive_storage_key,
    get_or_create_storage_salt,
    KeyDerivationError,
    InvalidInputError
)


class TestHKDFDerive:
    """Tests for HKDF key derivation function"""

    def test_hkdf_derive_valid_input(self):
        """Test HKDF derivation with valid input"""
        ikm = b"test_input_key_material"
        salt = b"test_salt"
        info = b"test_info"
        length = 32
        
        result = hkdf_derive(ikm, salt, info, length)
        
        assert len(result) == length
        assert result != ikm  # Should be different from input

    def test_hkdf_derive_empty_ikm(self):
        """Test HKDF derivation with empty IKM raises error"""
        with pytest.raises(InvalidInputError, match="Input key material cannot be empty"):
            hkdf_derive(b"", b"salt", b"info", 32)

    def test_hkdf_derive_invalid_length(self):
        """Test HKDF derivation with invalid length"""
        with pytest.raises(InvalidInputError, match="Length must be between 1 and 64 bytes"):
            hkdf_derive(b"ikm", b"salt", b"info", 0)

    def test_hkdf_derive_different_outputs(self):
        """Test that different inputs produce different outputs"""
        ikm1 = b"test_input_1"
        ikm2 = b"test_input_2"
        salt = b"salt"
        info = b"info"
        
        result1 = hkdf_derive(ikm1, salt, info, 32)
        result2 = hkdf_derive(ikm2, salt, info, 32)
        
        assert result1 != result2

    def test_hkdf_derive_same_inputs_same_output(self):
        """Test that same inputs produce same outputs (deterministic)"""
        ikm = b"test_input"
        salt = b"salt"
        info = b"info"
        
        result1 = hkdf_derive(ikm, salt, info, 32)
        result2 = hkdf_derive(ikm, salt, info, 32)
        
        assert result1 == result2


class TestDeriveStorageKey:
    """Tests for storage key derivation"""

    def test_derive_storage_key_valid(self):
        """Test storage key derivation with valid password"""
        password = b"test_password_123"
        salt = b"test_salt_32_bytes_________"
        
        result = derive_storage_key(password, salt)
        
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_derive_storage_key_empty_password(self):
        """Test storage key derivation with empty password"""
        with pytest.raises(InvalidInputError, match="Password must be at least 8 characters"):
            derive_storage_key(b"", b"salt_16_bytes____")

    def test_derive_storage_key_invalid_salt_length(self):
        """Test storage key derivation with invalid salt length"""
        with pytest.raises(InvalidInputError, match="Salt must be at least 16 bytes"):
            derive_storage_key(b"password_8", b"short")


class TestGetOrCreateStorageSalt:
    """Tests for storage salt management"""

    def test_get_or_create_storage_salt_creates_new(self):
        """Test that a new salt is created if none exists"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock the STORAGE_SALT_FILE path
            from core import key_schedule
            original_file = key_schedule.STORAGE_SALT_FILE
            key_schedule.STORAGE_SALT_FILE = Path(tmpdir) / "salt.bin"
            
            try:
                salt = get_or_create_storage_salt()
                assert len(salt) == 32
                assert key_schedule.STORAGE_SALT_FILE.exists()
                
                # Verify it's the same on second call
                salt2 = get_or_create_storage_salt()
                assert salt == salt2
            finally:
                key_schedule.STORAGE_SALT_FILE = original_file

    def test_get_or_create_storage_salt_loads_existing(self):
        """Test that existing salt is loaded correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            from core import key_schedule
            original_file = key_schedule.STORAGE_SALT_FILE
            key_schedule.STORAGE_SALT_FILE = Path(tmpdir) / "salt.bin"
            
            try:
                # Create a known salt
                known_salt = b"a" * 32
                key_schedule.STORAGE_SALT_FILE.write_bytes(known_salt)
                
                salt = get_or_create_storage_salt()
                assert salt == known_salt
            finally:
                key_schedule.STORAGE_SALT_FILE = original_file

    def test_get_or_create_storage_salt_invalid_length_recreates(self):
        """Test that invalid salt length triggers recreation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            from core import key_schedule
            original_file = key_schedule.STORAGE_SALT_FILE
            key_schedule.STORAGE_SALT_FILE = Path(tmpdir) / "salt.bin"
            
            try:
                # Create an invalid salt (wrong length)
                invalid_salt = b"short"
                key_schedule.STORAGE_SALT_FILE.write_bytes(invalid_salt)
                
                salt = get_or_create_storage_salt()
                assert len(salt) == 32
                assert salt != invalid_salt
            finally:
                key_schedule.STORAGE_SALT_FILE = original_file


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
