"""
Encrypted database operations for message storage
"""

import base64
import os
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.constants import APP_DIR
from core.key_schedule import hkdf_derive

__all__ = [
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

# Base64 helpers
b64e = lambda x: base64.b64encode(x).decode("utf-8")
b64d = lambda x: base64.b64decode(x.encode("utf-8") if isinstance(x, str) else x)


def init_db(db_path: Path = None) -> None:
    """Initialize the messages database with required tables"""
    if db_path is None:
        db_path = APP_DIR / "messages.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            msg_id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL,
            sender_fp TEXT NOT NULL,
            sender_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            body TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            encrypted INTEGER DEFAULT 0,
            reply_to_msg_id TEXT,
            thread_root_id TEXT,
            deleted INTEGER DEFAULT 0
        )
    """)
    
    # Create indexes for common queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_room_id ON messages(room_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_thread_root ON messages(thread_root_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sender_fp ON messages(sender_fp)")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            event TEXT NOT NULL,
            room_id TEXT,
            fingerprint TEXT,
            details TEXT
        )
    """)
    
    conn.commit()
    conn.close()


def store_message(msg_id: str, room_id: str, sender_fp: str, sender_name: str, 
                 kind: str, body: str, timestamp: int, encrypted: bool = True,
                 reply_to_msg_id: str = None, thread_root_id: str = None,
                 storage_key: bytes = None) -> None:
    """Store a message in the database with threading support
    
    Note: If storage_key is provided, sensitive metadata (sender_fp, room_id) is encrypted
    before storage. Message bodies are stored as-is (already E2E encrypted with room key).
    For full disk encryption, use filesystem encryption or SQLCipher.
    """
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Encrypt sensitive metadata if storage key is available
        if storage_key:
            # Derive a key for metadata encryption
            meta_key = hkdf_derive(
                ikm=storage_key,
                salt=b"0x1FC/db/meta/salt/v1",
                info=b"0x1FC/db/meta/key/v1",
                length=32
            )
            
            # Encrypt sender_fp and room_id
            try:
                sender_fp_enc = b64e(AESGCM(meta_key).encrypt(
                    os.urandom(12),
                    sender_fp.encode(),
                    b"0x1FC/db/sender_fp"
                ))
                room_id_enc = b64e(AESGCM(meta_key).encrypt(
                    os.urandom(12),
                    room_id.encode(),
                    b"0x1FC/db/room_id"
                ))
                sender_fp_stored = sender_fp_enc
                room_id_stored = room_id_enc
            except Exception as e:
                print(f"[ERROR] Metadata encryption failed, storing plaintext: {e}")
                sender_fp_stored = sender_fp
                room_id_stored = room_id
        else:
            sender_fp_stored = sender_fp
            room_id_stored = room_id
        
        cursor.execute("""
            INSERT OR REPLACE INTO messages 
            (msg_id, room_id, sender_fp, sender_name, kind, body, timestamp, encrypted, reply_to_msg_id, thread_root_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (msg_id, room_id_stored, sender_fp_stored, sender_name, kind, body, timestamp, 
              1 if encrypted else 0, reply_to_msg_id, thread_root_id))
        
        conn.commit()
        conn.close()
    except Exception as e:
        # Log database errors but don't fail the application
        print(f"[ERROR] Database error in store_message: {e}")


def get_thread_messages(thread_root_id: str, limit: int = 100, storage_key: bytes = None) -> list:
    """Retrieve all messages in a thread"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT msg_id, room_id, sender_fp, sender_name, kind, body, timestamp, reply_to_msg_id
            FROM messages
            WHERE thread_root_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
        """, (thread_root_id, limit))
        
        messages = []
        for row in cursor.fetchall():
            msg_id, room_id_stored, sender_fp_stored, sender_name, kind, body, timestamp, reply_to_msg_id = row
            
            # Decrypt metadata if storage key is available
            if storage_key:
                meta_key = hkdf_derive(
                    ikm=storage_key,
                    salt=b"0x1FC/db/meta/salt/v1",
                    info=b"0x1FC/db/meta/key/v1",
                    length=32
                )
                try:
                    # Try to decrypt sender_fp and room_id
                    sender_fp_bytes = AESGCM(meta_key).decrypt(
                        b64d(sender_fp_stored[:24]),  # nonce (first 16 base64 chars = 12 bytes)
                        b64d(sender_fp_stored),
                        b"0x1FC/db/sender_fp"
                    )
                    sender_fp = sender_fp_bytes.decode()
                    
                    room_id_bytes = AESGCM(meta_key).decrypt(
                        b64d(room_id_stored[:24]),
                        b64d(room_id_stored),
                        b"0x1FC/db/room_id"
                    )
                    room_id = room_id_bytes.decode()
                except Exception:
                    # If decryption fails, assume plaintext
                    sender_fp = sender_fp_stored
                    room_id = room_id_stored
            else:
                sender_fp = sender_fp_stored
                room_id = room_id_stored
            
            messages.append({
                "msg_id": msg_id,
                "room_id": room_id,
                "sender_fp": sender_fp,
                "sender_name": sender_name,
                "kind": kind,
                "body": body,
                "timestamp": timestamp,
                "reply_to_msg_id": reply_to_msg_id
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def get_reply_chain(msg_id: str, limit: int = 50, storage_key: bytes = None) -> list:
    """Get the reply chain for a message"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # First get the thread root
        cursor.execute("SELECT thread_root_id FROM messages WHERE msg_id = ?", (msg_id,))
        result = cursor.fetchone()
        
        if not result or not result[0]:
            return []
        
        thread_root_id = result[0]
        
        # Get all messages in thread
        cursor.execute("""
            SELECT msg_id, room_id, sender_fp, sender_name, kind, body, timestamp, reply_to_msg_id
            FROM messages
            WHERE thread_root_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
        """, (thread_root_id, limit))
        
        messages = []
        for row in cursor.fetchall():
            msg_id, room_id_stored, sender_fp_stored, sender_name, kind, body, timestamp, reply_to_msg_id = row
            
            # Decrypt metadata if storage key is available
            if storage_key:
                meta_key = hkdf_derive(
                    ikm=storage_key,
                    salt=b"0x1FC/db/meta/salt/v1",
                    info=b"0x1FC/db/meta/key/v1",
                    length=32
                )
                try:
                    sender_fp_bytes = AESGCM(meta_key).decrypt(
                        b64d(sender_fp_stored[:24]),
                        b64d(sender_fp_stored),
                        b"0x1FC/db/sender_fp"
                    )
                    sender_fp = sender_fp_bytes.decode()
                    
                    room_id_bytes = AESGCM(meta_key).decrypt(
                        b64d(room_id_stored[:24]),
                        b64d(room_id_stored),
                        b"0x1FC/db/room_id"
                    )
                    room_id = room_id_bytes.decode()
                except Exception:
                    sender_fp = sender_fp_stored
                    room_id = room_id_stored
            else:
                sender_fp = sender_fp_stored
                room_id = room_id_stored
            
            messages.append({
                "msg_id": msg_id,
                "room_id": room_id,
                "sender_fp": sender_fp,
                "sender_name": sender_name,
                "kind": kind,
                "body": body,
                "timestamp": timestamp,
                "reply_to_msg_id": reply_to_msg_id
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def get_messages(room_id: str, limit: int = 100, offset: int = 0, storage_key: bytes = None) -> list:
    """Retrieve messages from database for a room"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT msg_id, room_id, sender_fp, sender_name, kind, body, timestamp, encrypted
            FROM messages
            WHERE room_id = ?
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (room_id, limit, offset))
        
        messages = []
        for row in cursor.fetchall():
            msg_id, room_id_stored, sender_fp_stored, sender_name, kind, body, timestamp, encrypted = row
            
            # Decrypt metadata if storage key is available
            if storage_key:
                meta_key = hkdf_derive(
                    ikm=storage_key,
                    salt=b"0x1FC/db/meta/salt/v1",
                    info=b"0x1FC/db/meta/key/v1",
                    length=32
                )
                try:
                    sender_fp_bytes = AESGCM(meta_key).decrypt(
                        b64d(sender_fp_stored[:24]),
                        b64d(sender_fp_stored),
                        b"0x1FC/db/sender_fp"
                    )
                    sender_fp = sender_fp_bytes.decode()
                    
                    room_id_bytes = AESGCM(meta_key).decrypt(
                        b64d(room_id_stored[:24]),
                        b64d(room_id_stored),
                        b"0x1FC/db/room_id"
                    )
                    room_id = room_id_bytes.decode()
                except Exception:
                    sender_fp = sender_fp_stored
                    room_id = room_id_stored
            else:
                sender_fp = sender_fp_stored
                room_id = room_id_stored
            
            messages.append({
                "msg_id": msg_id,
                "room_id": room_id,
                "sender_fp": sender_fp,
                "sender_name": sender_name,
                "kind": kind,
                "body": body,
                "timestamp": timestamp,
                "encrypted": bool(encrypted)
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def search_messages(query: str, room_id: str = None, limit: int = 50, storage_key: bytes = None) -> list:
    """Search messages by content"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if room_id:
            cursor.execute("""
                SELECT msg_id, room_id, sender_fp, sender_name, kind, body, timestamp
                FROM messages
                WHERE room_id = ? AND body LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (room_id, f"%{query}%", limit))
        else:
            cursor.execute("""
                SELECT msg_id, room_id, sender_fp, sender_name, kind, body, timestamp
                FROM messages
                WHERE body LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (f"%{query}%", limit))
        
        messages = []
        for row in cursor.fetchall():
            msg_id, room_id_stored, sender_fp_stored, sender_name, kind, body, timestamp = row
            
            # Decrypt metadata if storage key is available
            if storage_key:
                meta_key = hkdf_derive(
                    ikm=storage_key,
                    salt=b"0x1FC/db/meta/salt/v1",
                    info=b"0x1FC/db/meta/key/v1",
                    length=32
                )
                try:
                    sender_fp_bytes = AESGCM(meta_key).decrypt(
                        b64d(sender_fp_stored[:24]),
                        b64d(sender_fp_stored),
                        b"0x1FC/db/sender_fp"
                    )
                    sender_fp = sender_fp_bytes.decode()
                    
                    room_id_bytes = AESGCM(meta_key).decrypt(
                        b64d(room_id_stored[:24]),
                        b64d(room_id_stored),
                        b"0x1FC/db/room_id"
                    )
                    room_id = room_id_bytes.decode()
                except Exception:
                    sender_fp = sender_fp_stored
                    room_id = room_id_stored
            else:
                sender_fp = sender_fp_stored
                room_id = room_id_stored
            
            messages.append({
                "msg_id": msg_id,
                "room_id": room_id,
                "sender_fp": sender_fp,
                "sender_name": sender_name,
                "kind": kind,
                "body": body,
                "timestamp": timestamp
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def delete_message(msg_id: str) -> bool:
    """Mark a message as deleted (soft delete)"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE messages SET deleted = 1 WHERE msg_id = ?", (msg_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def delete_thread(thread_root_id: str) -> bool:
    """Mark all messages in a thread as deleted (soft delete)"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("UPDATE messages SET deleted = 1 WHERE thread_root_id = ?", (thread_root_id,))
        
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_message_stats(room_id: str = None) -> dict:
    """Get statistics about stored messages"""
    try:
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if room_id:
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN encrypted = 1 THEN 1 ELSE 0 END) as encrypted
                FROM messages
                WHERE room_id = ?
            """, (room_id,))
        else:
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN encrypted = 1 THEN 1 ELSE 0 END) as encrypted
                FROM messages
            """)
        
        row = cursor.fetchone()
        conn.close()
        
        return {
            "total": row[0] or 0,
            "active": row[1] or 0,
            "encrypted": row[2] or 0
        }
    except Exception:
        return {"total": 0, "active": 0, "encrypted": 0}
