"""
Protocol key schedule module - HKDF-based key derivation with labeled contexts
This is a re-export of the core key_schedule for protocol-level use
"""

from core.key_schedule import hkdf_derive

__all__ = ['hkdf_derive']
