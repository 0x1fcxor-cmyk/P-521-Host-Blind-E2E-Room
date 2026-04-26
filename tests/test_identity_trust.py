"""
Unit tests for identity.trust module
"""

import pytest
import tempfile
from pathlib import Path

from identity.trust import (
    normalize_fp,
    short_fp,
    default_settings,
    TrustError
)
from identity.keys import Identity, generate_identity


class TestNormalizeFp:
    """Tests for fingerprint normalization"""

    def test_normalize_fp_valid(self):
        """Test normalization of valid fingerprint"""
        fp = "A1B2C3D4E5F67890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
        normalized = normalize_fp(fp)
        
        assert ":" not in normalized
        assert "-" not in normalized
        assert " " not in normalized
        assert len(normalized) == 64
        assert normalized.isupper()

    def test_normalize_fp_with_spaces(self):
        """Test normalization with spaces"""
        fp = "A1 B2 C3 D4 E5 F6 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90"
        normalized = normalize_fp(fp)
        
        assert " " not in normalized
        assert len(normalized) == 64

    def test_normalize_fp_empty(self):
        """Test normalization of empty fingerprint raises error"""
        with pytest.raises(ValueError, match="Fingerprint cannot be empty"):
            normalize_fp("")

    def test_normalize_fp_invalid_length(self):
        """Test normalization of invalid length raises error"""
        with pytest.raises(ValueError, match="Invalid fingerprint length"):
            normalize_fp("A1B2")

    def test_normalize_fp_invalid_hex(self):
        """Test normalization of invalid hex characters raises error"""
        with pytest.raises(ValueError, match="Fingerprint contains invalid hex characters"):
            normalize_fp("G" * 64)


class TestShortFp:
    """Tests for short fingerprint generation"""

    def test_short_fp_valid(self):
        """Test short fingerprint generation"""
        fp = "A" * 64
        short = short_fp(fp)
        
        assert len(short) == 16
        assert short == "AAAAAAAAAAAAAAAA"

    def test_short_fp_empty(self):
        """Test short fingerprint of empty string raises error"""
        with pytest.raises(ValueError, match="Fingerprint cannot be empty"):
            short_fp("")


class TestDefaultSettings:
    """Tests for default settings"""

    def test_default_settings_structure(self):
        """Test that default settings has expected structure"""
        settings = default_settings()
        
        assert isinstance(settings, dict)
        assert "display_name" in settings
        assert "max_file_size" in settings
        assert settings["max_file_size"] > 0


class TestTrustContact:
    """Tests for trust contact operations"""

    def test_trust_contact_integration(self):
        """Test trusting a contact with real identity"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test identity
            identity = generate_identity("test_password", tmpdir)
            
            # Trust a contact
            fp = "A" * 64
            name = "Test Contact"
            
            from identity.trust import trust_contact, load_trust, trusted_name
            
            trust_contact(identity, fp, name)
            
            trust = load_trust(identity)
            assert fp in trust["contacts_by_fingerprint"]
            assert trust["contacts_by_fingerprint"][fp]["name"] == name

    def test_trusted_name(self):
        """Test getting trusted name"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            
            fp = "B" * 64
            name = "Another Contact"
            
            from identity.trust import trust_contact, trusted_name
            
            trust_contact(identity, fp, name)
            retrieved_name = trusted_name(identity, fp)
            
            assert retrieved_name == name

    def test_trusted_name_unknown(self):
        """Test getting name for unknown contact"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            
            from identity.trust import trusted_name
            
            name = trusted_name(identity, "C" * 64)
            
            assert name is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
