"""
Identity module - Key generation, management, and trust
"""

from .keys import (
    Identity,
    generate_identity,
    load_identity,
    load_identity_from_file,
    fingerprint_from_der,
    public_to_pem,
    public_to_der,
    load_private_pem
)
from .trust import (
    get_settings,
    save_settings,
    load_trust,
    save_trust,
    trust_contact,
    trusted_name,
    default_settings,
    default_trust,
    normalize_fp
)

__all__ = [
    # Keys
    'Identity',
    'generate_identity',
    'load_identity',
    'load_identity_from_file',
    'fingerprint_from_der',
    'public_to_pem',
    'public_to_der',
    'load_private_pem',
    # Trust
    'get_settings',
    'save_settings',
    'load_trust',
    'save_trust',
    'trust_contact',
    'trusted_name',
    'default_settings',
    'default_trust',
    'normalize_fp'
]
