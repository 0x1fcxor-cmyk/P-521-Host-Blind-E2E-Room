"""
Storage module - Encrypted storage and database operations
"""

from .vault import StorageVault
from .encrypted_db import (
    init_db,
    store_message,
    get_thread_messages,
    get_reply_chain,
    get_messages,
    search_messages,
    delete_message,
    delete_thread,
    get_message_stats
)

__all__ = [
    'StorageVault',
    'init_db',
    'store_message',
    'get_thread_messages',
    'get_reply_chain',
    'get_messages',
    'search_messages',
    'delete_message',
    'delete_thread',
    'get_message_stats'
]
