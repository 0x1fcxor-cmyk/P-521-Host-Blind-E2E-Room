"""
Unit tests for protocol.invites module
"""

import pytest
import time

from protocol.invites import (
    build_e2e_invite,
    verify_e2e_invite,
    InviteError,
    InvalidInviteError,
    SignatureVerificationError
)
from identity.keys import generate_identity
import tempfile


class TestBuildE2EInvite:
    """Tests for building E2E invites"""

    def test_build_e2e_invite_valid(self):
        """Test building a valid E2E invite"""
        relay_link = "ws://example.com:8080"
        room_key = "test_room_key_32_bytes_long_"
        
        invite = build_e2e_invite(relay_link, room_key)
        
        assert relay_link in invite
        assert room_key in invite
        assert "#rk=" in invite

    def test_build_e2e_invite_with_identity(self):
        """Test building a signed E2E invite with identity"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            relay_link = "ws://example.com:8080"
            room_key = "test_room_key_32_bytes_long_"
            
            invite = build_e2e_invite(relay_link, room_key, identity, expires_in_hours=24, max_uses=1, role="member")
            
            assert relay_link in invite
            assert room_key in invite
            assert "#rk=" in invite
            assert "&sig=" in invite

    def test_build_e2e_invite_empty_relay_link(self):
        """Test building invite with empty relay link raises error"""
        with pytest.raises(ValueError, match="Relay link cannot be empty"):
            build_e2e_invite("", "room_key")

    def test_build_e2e_invite_empty_room_key(self):
        """Test building invite with empty room key raises error"""
        with pytest.raises(ValueError, match="Room key cannot be empty"):
            build_e2e_invite("ws://example.com", "")

    def test_build_e2e_invite_invalid_expires(self):
        """Test building invite with invalid expiration raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            
            with pytest.raises(ValueError, match="Expires in hours must be positive"):
                build_e2e_invite("ws://example.com", "room_key", identity, expires_in_hours=0)

    def test_build_e2e_invite_invalid_max_uses(self):
        """Test building invite with invalid max uses raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            
            with pytest.raises(ValueError, match="Max uses must be positive"):
                build_e2e_invite("ws://example.com", "room_key", identity, max_uses=0)


class TestVerifyE2EInvite:
    """Tests for verifying E2E invites"""

    def test_verify_e2e_invite_valid(self):
        """Test verifying a valid E2E invite"""
        relay_link = "ws://example.com:8080"
        room_key = "test_room_key_32_bytes_long_"
        
        invite = build_e2e_invite(relay_link, room_key)
        payload = verify_e2e_invite(invite)
        
        assert payload is not None
        assert "rk" in payload
        assert payload["rk"] == room_key

    def test_verify_e2e_invite_with_signature(self):
        """Test verifying a signed E2E invite"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity = generate_identity("test_password", tmpdir)
            relay_link = "ws://example.com:8080"
            room_key = "test_room_key_32_bytes_long_"
            
            invite = build_e2e_invite(relay_link, room_key, identity, expires_in_hours=24, max_uses=1, role="member")
            payload = verify_e2e_invite(invite, identity)
            
            assert payload is not None
            assert "rk" in payload
            assert payload["rk"] == room_key

    def test_verify_e2e_invite_empty(self):
        """Test verifying empty invite raises error"""
        with pytest.raises(InvalidInviteError, match="Invite link cannot be empty"):
            verify_e2e_invite("")

    def test_verify_e2e_invite_invalid_format(self):
        """Test verifying invite with invalid format raises error"""
        with pytest.raises(InvalidInviteError, match="Invalid invite format"):
            verify_e2e_invite("invalid_invite_link")

    def test_verify_e2e_invite_invalid_signature(self):
        """Test verifying invite with invalid signature raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            identity1 = generate_identity("password1", tmpdir)
            identity2 = generate_identity("password2", tmpdir)
            
            relay_link = "ws://example.com:8080"
            room_key = "test_room_key_32_bytes_long_"
            
            # Sign with identity1, try to verify with identity2
            invite = build_e2e_invite(relay_link, room_key, identity1, expires_in_hours=24, max_uses=1, role="member")
            
            with pytest.raises(SignatureVerificationError, match="Invalid signature"):
                verify_e2e_invite(invite, identity2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
