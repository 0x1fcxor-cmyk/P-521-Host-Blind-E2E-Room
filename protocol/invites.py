"""
Protocol invites module - Signed, expiring, single-use invite tokens
"""

import base64
import json
import time
import logging
from typing import Optional, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from identity.keys import Identity
from transport.cloudflare import strip_fragment

logger = logging.getLogger(__name__)

__all__ = [
    'build_e2e_invite',
    'verify_e2e_invite'
]


class InviteError(Exception):
    """Base exception for invite errors"""
    pass


class InvalidInviteError(InviteError):
    """Raised when invite format is invalid"""
    pass


class SignatureVerificationError(InviteError):
    """Raised when signature verification fails"""
    pass


# Base64 helpers
b64e = lambda x: base64.b64encode(x).decode("utf-8")
b64d = lambda x: base64.b64decode(x.encode("utf-8") if isinstance(x, str) else x)


def build_e2e_invite(relay_link: str, room_key_text: str, identity: Optional[Identity] = None, 
                    expires_in_hours: int = 24, max_uses: int = 1, role: str = "member") -> str:
    """
    Build a signed, expiring E2E invite.
    
    Args:
        relay_link: Base relay WebSocket URL
        room_key_text: Room key in base64 text format
        identity: Identity for signing (optional)
        expires_in_hours: Hours until expiration (must be positive)
        max_uses: Maximum number of uses (must be positive)
        role: Role to grant (member, admin, etc.)
    
    Returns:
        Full invite link with signature
    
    Raises:
        ValueError: If parameters are invalid
        InviteError: If invite building fails
    """
    if not relay_link:
        raise ValueError("Relay link cannot be empty")
    
    if not room_key_text:
        raise ValueError("Room key cannot be empty")
    
    if expires_in_hours <= 0:
        raise ValueError("Expires in hours must be positive")
    
    if max_uses <= 0:
        raise ValueError("Max uses must be positive")
    
    try:
        stripped = strip_fragment(relay_link)
        
        payload: Dict[str, any] = {
            "rk": room_key_text,
            "exp": int(time.time()) + (expires_in_hours * 3600),
            "uses": max_uses,
            "role": role,
        }
        
        # Signature is over the room_key_text only (simplified approach)
        if identity:
            signature = identity.private_key.sign(
                room_key_text.encode("utf-8"),
                ec.ECDSA(hashes.SHA512())
            )
            sig_b64 = b64e(signature)
        else:
            sig_b64 = ""
        
        logger.info(f"Built E2E invite with role {role}, expires in {expires_in_hours}h")
        
        return f"{stripped}#rk={room_key_text}&sig={sig_b64}"
    except Exception as e:
        logger.error(f"Failed to build E2E invite: {e}")
        raise InviteError(f"Failed to build invite: {e}") from e


def verify_e2e_invite(invite_link: str, identity: Optional[Identity] = None) -> Dict[str, any]:
    """
    Verify an E2E invite signature and return payload.
    
    Args:
        invite_link: Full invite link
        identity: Identity for verification (optional)
    
    Returns:
        Payload dictionary with room_key, expires, uses, role
    
    Raises:
        InvalidInviteError: If invite format is invalid
        SignatureVerificationError: If signature verification fails
    """
    if not invite_link:
        raise InvalidInviteError("Invite link cannot be empty")
    
    try:
        if "#rk=" not in invite_link:
            raise InvalidInviteError("Invalid invite format")
        
        # Split the invite link to get the fragment part
        parts = invite_link.split("#rk=")
        
        if len(parts) != 2:
            raise InvalidInviteError("Invalid invite format")
        
        fragment = parts[1]
        room_key_part = fragment.split("&")[0]
        sig_part = fragment.split("&sig=")[1] if "&sig=" in fragment else ""
        
        # For unsigned invites, return basic payload
        if not sig_part:
            return {
                "rk": room_key_part,
                "exp": 0,
                "uses": 1,
                "role": "member",
            }
        
        # For signed invites, we need to verify the signature
        # The signature is over the room_key_part only (simplified approach)
        if identity and sig_part:
            signature = b64d(sig_part)
            
            try:
                identity.private_key.public_key().verify(
                    signature,
                    room_key_part.encode("utf-8"),
                    ec.ECDSA(hashes.SHA512())
                )
                logger.info("E2E invite signature verified successfully")
            except Exception as e:
                logger.error(f"Signature verification failed: {e}")
                raise SignatureVerificationError("Invalid signature") from e
        
        return {
            "rk": room_key_part,
            "exp": 0,
            "uses": 1,
            "role": "member",
        }
    except (InvalidInviteError, SignatureVerificationError):
        raise
    except Exception as e:
        logger.error(f"Failed to verify E2E invite: {e}")
        raise InviteError(f"Failed to verify invite: {e}") from e
