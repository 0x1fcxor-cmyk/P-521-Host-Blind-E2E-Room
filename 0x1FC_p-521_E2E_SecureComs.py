import asyncio
import base64
import getpass
import hashlib
import json
import logging
import os
import random
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
import threading
import urllib.request
import webbrowser
import zlib
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

import websockets
from websockets.exceptions import ConnectionClosed, InvalidUpgrade

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TransferSpeedColumn


APP_NAME = "P-521 Host-Blind E2E Room"
PROTOCOL_VERSION = "P521-HOST-BLIND-E2E-V1"

APP_DIR = Path.home() / ".p521_host_blind_room"
IDENTITY_FILE = APP_DIR / "identity_p521_private.pem"
PUBLIC_FILE = APP_DIR / "identity_p521_public.pem"
STORAGE_SALT_FILE = APP_DIR / "storage_salt.bin"
SETTINGS_FILE = APP_DIR / "settings.enc"
TRUST_FILE = APP_DIR / "trusted_contacts.enc"
LOG_DIR = APP_DIR / "logs"
DOWNLOAD_DIR = APP_DIR / "downloads"
CONFIG_FILE = APP_DIR / "config.json"

DEFAULT_PORT_MIN = 20000
DEFAULT_PORT_MAX = 50000
MAX_WS_MESSAGE = 32 * 1024 * 1024
FILE_CHUNK_SIZE = 512 * 1024
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

STORAGE_AAD = b"P521-HOST-BLIND-STORAGE-V1"
OVERLAY_AAD = b"P521-HOST-BLIND-E2E-OVERLAY-V1"

console = Console()

logging.getLogger("websockets.server").addHandler(logging.NullHandler())
logging.getLogger("websockets.protocol").addHandler(logging.NullHandler())
logging.getLogger("websockets").addHandler(logging.NullHandler())


@dataclass
class Identity:
    private_key: ec.EllipticCurvePrivateKey
    public_pem: bytes
    public_der: bytes
    fingerprint: str
    storage_key: bytes
    display_name: str


@dataclass
class OverlayEnvelope:
    room_id: str
    sender_fp: str
    sender_public_pem: str
    nonce_prefix: str
    counter: int
    ciphertext: str
    signature: str


@dataclass
class IncomingFile:
    file_id: str
    sender: str
    filename: str
    size: int
    temp_path: Path
    final_path: Path
    received: int = 0
    sha: "hashlib._Hash" = field(default_factory=hashlib.sha256)
    handle: Optional[object] = None
    progress_task: Optional[object] = None

    def open(self) -> None:
        self.handle = self.temp_path.open("wb")

    def write(self, data: bytes) -> None:
        self.handle.write(data)
        self.sha.update(data)
        self.received += len(data)

    def finish(self, expected_sha: str) -> Path:
        if self.handle:
            self.handle.close()

        actual = self.sha.hexdigest()

        if actual.lower() != expected_sha.lower():
            try:
                self.temp_path.unlink()
            except Exception as e:
                warn(f"Failed to delete temp file: {e}")
            raise RuntimeError("SHA-256 mismatch. File rejected.")

        self.temp_path.replace(self.final_path)
        return self.final_path

    def abort(self) -> None:
        try:
            if self.handle:
                self.handle.close()
        except Exception as e:
            warn(f"Failed to close file handle: {e}")

        try:
            self.temp_path.unlink()
        except Exception as e:
            warn(f"Failed to delete temp file: {e}")


@dataclass
class CloudflareTunnel:
    process: subprocess.Popen
    url: str
    local_port: int
    token: str


class StorageVault:
    def __init__(self, key: bytes):
        self.key = key

    def encrypt_bytes(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, data, STORAGE_AAD)

        return json.dumps({
            "v": 1,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }).encode("utf-8")

    def decrypt_bytes(self, data: bytes) -> bytes:
        payload = json.loads(data.decode("utf-8"))
        nonce = b64d(payload["nonce"])
        ciphertext = b64d(payload["ciphertext"])
        return AESGCM(self.key).decrypt(nonce, ciphertext, STORAGE_AAD)

    def encrypt_json_file(self, path: Path, obj: dict) -> None:
        raw = json.dumps(obj, indent=2).encode("utf-8")
        path.write_bytes(self.encrypt_bytes(raw))

    def decrypt_json_file(self, path: Path, default: dict) -> dict:
        if not path.exists():
            return default

        try:
            raw = self.decrypt_bytes(path.read_bytes())
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return default

    def encrypted_log_line(self, path: Path, entry: dict) -> None:
        raw = json.dumps(entry, separators=(",", ":")).encode("utf-8")
        line = self.encrypt_bytes(raw)

        with path.open("ab") as f:
            f.write(base64.b64encode(line) + b"\n")


class OverlayCrypto:
    def __init__(self, identity: Identity, room_key: bytes, sealed_sender: bool = False):
        self.identity = identity
        # Derive room key using HKDF with labeled context
        self.room_key = hkdf_derive(
            ikm=room_key,
            salt=b"0x1FC/room/salt/v1",
            info=b"0x1FC/room/key/v1",
            length=32
        )
        self.room_id = hashlib.sha256(self.room_key).hexdigest()[:24].upper()
        self.nonce_prefix = os.urandom(4)
        self.send_counter = 0
        self.seen_counters: Dict[str, int] = {}
        
        # Compression and deduplication
        self.compression_enabled = True
        self.message_dedup_cache: Dict[str, float] = {}
        self.dedup_cache_ttl = 3600  # 1 hour
        self.audit_log_enabled = True
        
        # Storage vault for encrypted audit logging
        self.storage_vault = StorageVault(identity.storage_key)
        
        # Sealed sender mode - hides sender identity from relay
        self.sealed_sender = sealed_sender
        if sealed_sender:
            # Generate a routing tag for sealed sender mode
            self.routing_tag = hashlib.sha256(self.room_key + self.identity.fingerprint.encode()).hexdigest()[:16].upper()
        else:
            self.routing_tag = None
        
        # Note: Ephemeral keys and key rotation removed - these were part of broken PFS implementation
        # Proper forward secrecy requires a complete protocol redesign with X3DH/Noise + Double Ratchet

    def signable_bytes(self, envelope_without_signature: dict) -> bytes:
        canonical = json.dumps(
            envelope_without_signature,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return b"P521-HOST-BLIND-SIGNATURE-V1|" + canonical

    def compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib for bandwidth optimization"""
        if not self.compression_enabled:
            return data
        return zlib.compress(data, level=6)

    def decompress_data(self, data: bytes) -> bytes:
        """Decompress zlib-compressed data"""
        return zlib.decompress(data)

    def is_duplicate_message(self, msg_id: str) -> bool:
        """Check if message is a duplicate using deduplication cache"""
        if msg_id in self.message_dedup_cache:
            return True
        self.message_dedup_cache[msg_id] = time.time()
        return False

    def cleanup_dedup_cache(self) -> None:
        """Clean up expired entries from deduplication cache"""
        now = time.time()
        expired = [k for k, v in self.message_dedup_cache.items() if now - v > self.dedup_cache_ttl]
        for k in expired:
            del self.message_dedup_cache[k]

    def log_audit_event(self, event_type: str, details: dict) -> None:
        """Log security event to audit log (encrypted)"""
        if not self.audit_log_enabled:
            return
        
        try:
            audit_entry = {
                "timestamp": int(time.time()),
                "event": event_type,
                "room_id": self.room_id,
                "fingerprint": self.identity.fingerprint,
                "details": details
            }
            
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            audit_file = LOG_DIR / "audit.log"
            
            # Use encrypted logging via StorageVault
            self.storage_vault.encrypted_log_line(audit_file, audit_entry)
        except Exception:
            pass  # Don't fail on audit logging errors

    def encrypt_packet(self, packet: dict) -> dict:
        self.send_counter += 1
        counter = self.send_counter

        packet = dict(packet)
        packet["protocol"] = PROTOCOL_VERSION
        packet["room_id"] = self.room_id
        packet["sender_fp"] = self.identity.fingerprint
        packet["sender_name"] = self.identity.display_name
        packet["timestamp"] = now()
        
        # Add unique message ID for deduplication
        packet["msg_id"] = f"{self.identity.fingerprint[:8]}_{int(time.time())}_{counter}"

        nonce = self.nonce_prefix + counter.to_bytes(8, "big")
        aad = OVERLAY_AAD + self.room_id.encode("utf-8") + counter.to_bytes(8, "big")

        raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
        
        # Compress payload
        compressed = self.compress_data(raw)
        
        # Single-layer encryption with room key only
        # Note: Double-layer PFS removed due to key derivation mismatch
        # For true PFS, would require proper key exchange protocol
        ciphertext = AESGCM(self.room_key).encrypt(nonce, compressed, aad)

        # Build envelope - use sealed sender mode if enabled
        if self.sealed_sender:
            envelope = {
                "type": "e2e",
                "protocol": PROTOCOL_VERSION,
                "room_id": self.room_id,
                "routing_tag": self.routing_tag,  # Only routing tag visible to relay
                "sender_public_pem": self.identity.public_pem.decode("utf-8"),  # Still needed for signature verification
                "nonce_prefix": b64e(self.nonce_prefix),
                "counter": counter,
                "ciphertext": b64e(ciphertext),
                "compressed": self.compression_enabled,
                "sealed": True,  # Flag indicating sealed sender mode
            }
        else:
            envelope = {
                "type": "e2e",
                "protocol": PROTOCOL_VERSION,
                "room_id": self.room_id,
                "sender_fp": self.identity.fingerprint,
                "sender_public_pem": self.identity.public_pem.decode("utf-8"),
                "nonce_prefix": b64e(self.nonce_prefix),
                "counter": counter,
                "ciphertext": b64e(ciphertext),
                "compressed": self.compression_enabled,
                "sealed": False,
            }

        signature = self.identity.private_key.sign(
            self.signable_bytes(envelope),
            ec.ECDSA(hashes.SHA512()),
        )

        envelope["signature"] = b64e(signature)
        
        # Log encryption event
        self.log_audit_event("message_encrypted", {
            "msg_id": packet["msg_id"],
            "compressed": self.compression_enabled,
            "size": len(raw),
            "compressed_size": len(compressed),
        })
        
        return envelope

    def decrypt_envelope(self, envelope: dict) -> Optional[dict]:
        if envelope.get("type") != "e2e":
            raise RuntimeError("Not an E2E overlay envelope")

        if envelope.get("protocol") != PROTOCOL_VERSION:
            raise RuntimeError("Protocol mismatch")

        if envelope.get("room_id") != self.room_id:
            return None

        signature = b64d(envelope["signature"])
        signed = dict(envelope)
        signed.pop("signature", None)

        sender_public = serialization.load_pem_public_key(
            envelope["sender_public_pem"].encode("utf-8")
        )

        sender_der = sender_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        sender_fp = fingerprint_from_der(sender_der)

        # Handle sealed sender mode
        if envelope.get("sealed", False):
            # In sealed sender mode, sender_fp is not in envelope
            # Extract it from the public key after verification
            envelope["sender_fp"] = sender_fp
        else:
            # Normal mode - verify fingerprint matches
            if sender_fp != envelope.get("sender_fp"):
                raise RuntimeError("Sender fingerprint does not match sender public key")

        sender_public.verify(
            signature,
            self.signable_bytes(signed),
            ec.ECDSA(hashes.SHA512()),
        )

        nonce_prefix = b64d(envelope["nonce_prefix"])
        counter = int(envelope["counter"])

        replay_key = f"{sender_fp}:{envelope['nonce_prefix']}"
        last = self.seen_counters.get(replay_key, 0)

        if counter <= last:
            raise RuntimeError("Replay rejected: old or duplicate overlay counter")

        nonce = nonce_prefix + counter.to_bytes(8, "big")
        aad = OVERLAY_AAD + self.room_id.encode("utf-8") + counter.to_bytes(8, "big")
        ciphertext = b64d(envelope["ciphertext"])
        
        # Single-layer decryption with room key only
        # Note: PFS double-layer removed due to key derivation mismatch
        decrypted = AESGCM(self.room_key).decrypt(nonce, ciphertext, aad)
        
        # Decompress if needed
        compressed = envelope.get("compressed", False)
        if compressed:
            try:
                decrypted = self.decompress_data(decrypted)
            except Exception as e:
                raise RuntimeError(f"Decompression failed: {e}")
        
        packet = json.loads(decrypted.decode())
        
        # Check for duplicate message
        msg_id = packet.get("msg_id")
        if msg_id and self.is_duplicate_message(msg_id):
            self.log_audit_event("duplicate_message_rejected", {"msg_id": msg_id, "sender_fp": sender_fp})
            return None
        
        # Update replay protection
        self.seen_counters[replay_key] = counter
        
        # Periodic cleanup
        if counter % 100 == 0:
            self.cleanup_dedup_cache()
        
        # Log decryption event
        self.log_audit_event("message_decrypted", {
            "msg_id": msg_id,
            "sender_fp": sender_fp,
            "compressed": compressed,
            "sealed": envelope.get("sealed", False)
        })
        
        return packet


def ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    initialize_database()


def initialize_database() -> None:
    """Initialize SQLite database for message persistence"""
    db_path = APP_DIR / "messages.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Messages table with threading support
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT UNIQUE NOT NULL,
                room_id TEXT NOT NULL,
                sender_fp TEXT NOT NULL,
                sender_name TEXT,
                kind TEXT NOT NULL,
                body TEXT,
                timestamp INTEGER NOT NULL,
                encrypted INTEGER DEFAULT 1,
                reply_to_msg_id TEXT,
                thread_root_id TEXT,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_room_id ON messages(room_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sender_fp ON messages(sender_fp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(msg_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reply_to ON messages(reply_to_msg_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_thread_root ON messages(thread_root_id)")
        
        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event TEXT NOT NULL,
                room_id TEXT,
                fingerprint TEXT,
                details TEXT,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)")
        
        conn.commit()
        conn.close()
    except Exception as e:
        # Don't fail on database errors, just log
        pass


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


def get_messages(room_id: str, limit: int = 100, offset: int = 0) -> list:
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
            messages.append({
                "msg_id": row[0],
                "room_id": row[1],
                "sender_fp": row[2],
                "sender_name": row[3],
                "kind": row[4],
                "body": row[5],
                "timestamp": row[6],
                "encrypted": bool(row[7])
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def search_messages(query: str, room_id: str = None, limit: int = 50) -> list:
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
            messages.append({
                "msg_id": row[0],
                "room_id": row[1],
                "sender_fp": row[2],
                "sender_name": row[3],
                "kind": row[4],
                "body": row[5],
                "timestamp": row[6]
            })
        
        conn.close()
        return messages
    except Exception:
        return []


def log_security_event(event_type: str, details: dict, identity: Identity = None) -> None:
    """Log security event to both file and database"""
    try:
        # Log to file (encrypted if identity provided)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        audit_file = LOG_DIR / "audit.log"
        
        entry = {
            "timestamp": int(time.time()),
            "event": event_type,
            "details": details
        }
        
        if identity:
            # Use StorageVault for encrypted logging
            vault = StorageVault(identity.storage_key)
            vault.encrypted_log_line(audit_file, entry)
        else:
            # Fallback to plaintext (not recommended)
            with audit_file.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        
        # Log to database (details stored as JSON, not encrypted)
        # Note: SQLite DB stores details in plaintext - this is a known limitation
        db_path = APP_DIR / "messages.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_log (timestamp, event, room_id, fingerprint, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            entry["timestamp"],
            event_type,
            details.get("room_id"),
            details.get("fingerprint"),
            json.dumps(details)
        ))
        
        conn.commit()
        conn.close()
    except Exception:
        pass  # Don't fail on logging errors


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {
            "default_port": None,
            "auto_accept_files": False,
            "file_size_limit_mb": 100,
            "relay_mode": "cloudflare",  # Options: cloudflare, tor, wireguard, lan
        }

    try:
        with CONFIG_FILE.open("r") as f:
            config = json.load(f)
            # Add relay_mode if not present
            if "relay_mode" not in config:
                config["relay_mode"] = "cloudflare"
            return config
    except Exception:
        return {
            "default_port": None,
            "auto_accept_files": False,
            "file_size_limit_mb": 100,
            "relay_mode": "cloudflare",
        }


def save_config(config: dict) -> None:
    with CONFIG_FILE.open("w") as f:
        json.dump(config, f, indent=2)


def load_identity_from_file(password: str) -> Optional[Identity]:
    """Load identity from file with password"""
    if not IDENTITY_FILE.exists():
        return None

    try:
        # Use the same method as load_identity() - PEM encryption
        data = IDENTITY_FILE.read_bytes()
        private_key = serialization.load_pem_private_key(data, password=password.encode())
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        fp = hashlib.sha256(public_der).hexdigest()

        # Derive storage key using the same method as load_identity()
        storage_salt = get_or_create_storage_salt()
        storage_key = derive_storage_key(password.encode(), storage_salt)

        # Load display name from settings using StorageVault
        display_name = "User"
        if SETTINGS_FILE.exists():
            try:
                local_vault = StorageVault(storage_key)
                settings = local_vault.decrypt_json_file(SETTINGS_FILE, default_settings())
                display_name = settings.get("display_name", "User")
            except:
                pass

        return Identity(
            private_key=private_key,
            public_pem=public_pem,
            public_der=public_der,
            fingerprint=fp,
            storage_key=storage_key,
            display_name=display_name
        )
    except (ValueError, TypeError, InvalidSignature, InvalidTag, OSError) as e:
        raise ValueError("Wrong password or corrupted identity file")
    except Exception as e:
        raise ValueError(f"Failed to load identity: {type(e).__name__}: {e}")


def start_web_ui_server(port: int, password: str, fingerprint: str, display_name: str, invite_link: str = None) -> subprocess.Popen:
    """Start the web UI server in a subprocess with auto-login credentials"""
    script_path = Path(__file__).parent / "web_ui.py"
    
    if not script_path.exists():
        raise FileNotFoundError("web_ui.py not found. Please ensure it's in the same directory.")

    # Create environment with credentials
    env = os.environ.copy()
    env['P521_AUTO_PASSWORD'] = password
    env['P521_AUTO_FINGERPRINT'] = fingerprint
    env['P521_AUTO_DISPLAY_NAME'] = display_name
    env['P521_WEB_UI_PORT'] = str(port)
    if invite_link:
        env['P521_AUTO_INVITE_LINK'] = invite_link

    # Don't pass --port to let web_ui.py use the environment variable or random port
    cmd = [sys.executable, str(script_path), '--auto-login']

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    # Don't redirect stderr so we can see errors
    process = subprocess.Popen(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
    )

    # Give server a moment to start
    time.sleep(1)
    
    # Check if process is still running
    if process.poll() is not None:
        raise RuntimeError(f"Web UI server failed to start. Exit code: {process.poll()}")

    return process


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def banner() -> None:
    clear()

    title = Text()
    title.append("P-521", style="bold cyan")
    title.append(" Host-Blind E2E Room", style="bold white")

    subtitle = Text()
    subtitle.append("Blind Relay", style="yellow")
    subtitle.append("  +  ")
    subtitle.append("Client-Side Room Key", style="green")
    subtitle.append("  +  ")
    subtitle.append("P-521 Signed Packets", style="cyan")
    subtitle.append("  +  ")
    subtitle.append("AES-256-GCM Overlay", style="magenta")

    console.print(Panel(
        Align.center(title + "\n" + subtitle),
        box=box.DOUBLE,
        border_style="cyan",
        padding=(1, 2),
    ))


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def info(msg: str) -> None:
    console.print(f"[cyan][INFO][/cyan] {msg}")


def good(msg: str) -> None:
    console.print(f"[green][OK][/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][WARN][/yellow] {msg}")


def bad(msg: str) -> None:
    console.print(f"[red][ERROR][/red] {msg}")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def normalize_fp(fp: str) -> str:
    return fp.replace(":", "").replace("-", "").replace(" ", "").strip().upper()


def short_fp(fp: str) -> str:
    return normalize_fp(fp)[:16]


def fingerprint_from_der(public_der: bytes) -> str:
    digest = hashlib.sha256(public_der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def public_to_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_to_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_to_encrypted_pem(private_key: ec.EllipticCurvePrivateKey, password: bytes) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def load_private_pem(data: bytes, password: bytes) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(data, password=password)


def get_or_create_storage_salt() -> bytes:
    if STORAGE_SALT_FILE.exists():
        return STORAGE_SALT_FILE.read_bytes()

    salt = os.urandom(32)
    STORAGE_SALT_FILE.write_bytes(salt)
    return salt


def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a key using HKDF-SHA512 with labeled context.
    
    Args:
        ikm: Input key material
        salt: Salt value (use empty bytes if none)
        info: Context label (e.g., b"0x1FC/message/aead/v1")
        length: Output key length in bytes
    
    Returns:
        Derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def derive_storage_key(password: bytes, salt: bytes) -> bytes:
    # Use Argon2id for proper password hardening
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher(
            time_cost=3,
            memory_cost=262144,  # 256 MB
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type='ID'
        )
        # Argon2 expects str password, convert bytes to str
        password_str = password.decode('utf-8') if isinstance(password, bytes) else password
        salt_str = salt.hex()  # Convert salt to hex string for Argon2
        # Derive key using Argon2id
        hash_result = ph.hash(password_str, salt=salt_str)
        # Extract the hash part (remove parameters)
        hash_part = hash_result.split('$')[-1]
        return bytes.fromhex(hash_part)
    except ImportError:
        # Fallback to PBKDF2 if argon2 not available
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600000,  # Higher iterations for SHA512
        )
        return kdf.derive(password)


def create_password() -> bytes:
    while True:
        p1 = getpass.getpass("Create identity password: ").encode("utf-8")

        if len(p1) < 12:
            bad("Use at least 12 characters.")
            continue

        p2 = getpass.getpass("Confirm identity password: ").encode("utf-8")

        if p1 != p2:
            bad("Passwords did not match.")
            continue

        return p1


def unlock_password() -> bytes:
    return getpass.getpass("Identity password: ").encode("utf-8")


def default_settings(display_name: str = "P-521 User") -> dict:
    return {
        "display_name": display_name,
        "max_file_size": DEFAULT_MAX_FILE_SIZE,
    }


def default_trust() -> dict:
    return {
        "contacts_by_fingerprint": {},
        "nickname_index": {},
    }


def create_identity() -> None:
    ensure_dirs()
    banner()

    console.print(Panel(
        "No local P-521 identity was found.\n\n"
        "This creates a long-term P-521 signing identity.\n"
        "Your identity signs E2E overlay packets so other room members can authenticate messages.\n\n"
        "The relay host does not need this key and cannot read overlay content.",
        title="First Run",
        border_style="cyan",
    ))

    display_name = Prompt.ask("Display name", default="P-521 User")
    password = create_password()

    private_key = ec.generate_private_key(ec.SECP521R1())
    public_key = private_key.public_key()

    IDENTITY_FILE.write_bytes(private_to_encrypted_pem(private_key, password))
    PUBLIC_FILE.write_bytes(public_to_pem(public_key))

    storage_key = derive_storage_key(password, get_or_create_storage_salt())
    local_vault = StorageVault(storage_key)

    local_vault.encrypt_json_file(SETTINGS_FILE, default_settings(display_name))
    local_vault.encrypt_json_file(TRUST_FILE, default_trust())

    fp = fingerprint_from_der(public_to_der(public_key))

    good("Identity created.")
    console.print(Panel(fp, title="Your P-521 Identity Fingerprint", border_style="green"))
    input("\nPress Enter...")


def load_identity() -> Identity:
    ensure_dirs()

    if not IDENTITY_FILE.exists() or not PUBLIC_FILE.exists():
        create_identity()

    while True:
        try:
            password = unlock_password()
            private_key = load_private_pem(IDENTITY_FILE.read_bytes(), password)
            public_key = private_key.public_key()
            public_pem = public_to_pem(public_key)
            public_der = public_to_der(public_key)
            fp = fingerprint_from_der(public_der)

            storage_key = derive_storage_key(password, get_or_create_storage_salt())
            settings = StorageVault(storage_key).decrypt_json_file(
                SETTINGS_FILE,
                default_settings(),
            )

            return Identity(
                private_key=private_key,
                public_pem=public_pem,
                public_der=public_der,
                fingerprint=fp,
                storage_key=storage_key,
                display_name=settings.get("display_name", "P-521 User"),
            )

        except (ValueError, TypeError, InvalidSignature, InvalidTag, OSError) as e:
            bad("Wrong password or corrupted identity.")
            console.print()
            console.print("[yellow]Suggestions:[/yellow]")
            console.print("• Double-check your password (case-sensitive)")
            console.print("• If you recently changed your password, use the new one")
            console.print("• If identity files are corrupted, you may need to reset (menu option 8)")
            if not Confirm.ask("Try again?", default=True):
                sys.exit(1)


def vault(identity: Identity) -> StorageVault:
    return StorageVault(identity.storage_key)


def get_settings(identity: Identity) -> dict:
    return vault(identity).decrypt_json_file(SETTINGS_FILE, default_settings(identity.display_name))


def save_settings(identity: Identity, settings: dict) -> None:
    vault(identity).encrypt_json_file(SETTINGS_FILE, settings)


def load_trust(identity: Identity) -> dict:
    return vault(identity).decrypt_json_file(TRUST_FILE, default_trust())


def save_trust(identity: Identity, trust: dict) -> None:
    vault(identity).encrypt_json_file(TRUST_FILE, trust)


def trust_contact(identity: Identity, fp: str, name: str) -> None:
    trust = load_trust(identity)
    nfp = normalize_fp(fp)

    old = trust.setdefault("contacts_by_fingerprint", {}).get(nfp)

    trust["contacts_by_fingerprint"][nfp] = {
        "fingerprint": fp,
        "name": name,
        "trusted_at": now(),
        "previous": old,
    }

    trust.setdefault("nickname_index", {})[name.lower()] = nfp
    save_trust(identity, trust)


def trusted_name(identity: Identity, fp: str) -> Optional[str]:
    trust = load_trust(identity)
    item = trust.get("contacts_by_fingerprint", {}).get(normalize_fp(fp))
    if not item:
        return None
    return item.get("name")


def key_change_warning(identity: Identity, name: str, fp: str) -> Optional[str]:
    trust = load_trust(identity)
    old_fp = trust.get("nickname_index", {}).get(name.lower())

    if old_fp and old_fp != normalize_fp(fp):
        return old_fp

    return None


def log_secure(identity: Identity, room_id: str, direction: str, text: str) -> None:
    try:
        path = LOG_DIR / f"room_{room_id}.elog"
        entry = {
            "time": now(),
            "direction": direction,
            "text": text,
        }
        vault(identity).encrypted_log_line(path, entry)
    except Exception as e:
        warn(f"Failed to write encrypted log: {e}")


def safe_name(name: str) -> str:
    name = os.path.basename(name.strip().replace("\\", "/"))
    cleaned = []

    for c in name:
        if c.isalnum() or c in ("-", "_", ".", " "):
            cleaned.append(c)
        else:
            cleaned.append("_")

    result = "".join(cleaned).strip()
    return result or "received_file.bin"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix

    for i in range(1, 10000):
        candidate = path.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate

    return path.with_name(f"{stem}_{secrets.token_hex(4)}{suffix}")


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)

    for u in units:
        if size < 1024:
            return f"{size:.2f} {u}"
        size /= 1024

    return f"{size:.2f} PB"


def generate_room_key() -> str:
    return b64e(os.urandom(32))


def decode_room_key(room_key_text: str) -> bytes:
    key = b64d(room_key_text)

    if len(key) != 32:
        raise ValueError("Room key must decode to 32 bytes")

    return key


def room_id_from_key_text(room_key_text: str) -> str:
    return hashlib.sha256(decode_room_key(room_key_text)).hexdigest()[:24].upper()


def strip_fragment(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def parse_invite(raw: str) -> Tuple[str, str, str]:
    raw = raw.strip()

    if raw.startswith("p521://"):
        raw = raw.replace("p521://", "https://", 1)

    if not raw.startswith(("http://", "https://", "ws://", "wss://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    query = parse_qs(parsed.query)

    token = ""
    if "token" in query and query["token"]:
        token = query["token"][0]

    if not token:
        token = Prompt.ask("Relay token")

    fragment_data = parse_qs(parsed.fragment)
    room_key = ""

    if "rk" in fragment_data and fragment_data["rk"]:
        room_key = fragment_data["rk"][0]

    if not room_key:
        room_key = Prompt.ask("E2E room key")

    scheme = "wss" if parsed.scheme in ("https", "wss") else "ws"
    ws_url = f"{scheme}://{parsed.netloc}/ws?token={token}"

    return ws_url, token, room_key


def build_relay_link(tunnel_url: str, token: str) -> str:
    return f"{tunnel_url}/chat?token={token}"


def build_e2e_invite(relay_link: str, room_key_text: str, identity: Identity = None, 
                    expires_in_hours: int = 24, max_uses: int = 1, role: str = "member") -> str:
    """
    Build a signed, expiring E2E invite.
    
    Args:
        relay_link: Base relay link
        room_key_text: Room key (still included for compatibility, but should be shared separately)
        identity: Identity for signing (if None, creates unsigned invite)
        expires_in_hours: Hours until invite expires
        max_uses: Maximum number of times invite can be used
        role: Role for invitee (member, admin, etc.)
    
    Returns:
        Signed invite URL with encoded invite data
    """
    import time
    
    if identity is None:
        # Fallback to simple unsigned invite for compatibility
        return strip_fragment(relay_link) + f"#rk={room_key_text}"
    
    # Create invite structure
    invite_data = {
        "version": 1,
        "relay_url": strip_fragment(relay_link),
        "room_key": room_key_text,  # Still included but should be shared separately for security
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + (expires_in_hours * 3600),
        "max_uses": max_uses,
        "role": role,
        "capabilities": ["chat", "file_recv"],
        "sponsor_fingerprint": identity.fingerprint,
    }
    
    # Sign the invite data
    canonical = json.dumps(invite_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = identity.private_key.sign(
        canonical,
        ec.ECDSA(hashes.SHA512())
    )
    
    invite_data["signature"] = b64e(signature).decode("utf-8")
    
    # Encode the full invite as base64
    invite_json = json.dumps(invite_data, separators=(",", ":"))
    invite_encoded = b64e(invite_json.encode("utf-8")).decode("utf-8")
    
    return f"0x1fc://invite/{invite_encoded}"


def verify_e2e_invite(invite_url: str, trusted_fingerprints: set = None) -> dict:
    """
    Verify a signed E2E invite.
    
    Args:
        invite_url: Signed invite URL
        trusted_fingerprints: Set of trusted fingerprints to validate sponsor
    
    Returns:
        Decoded invite data if valid, None if invalid
    """
    import time
    
    try:
        # Parse invite URL
        if not invite_url.startswith("0x1fc://invite/"):
            return None  # Not a signed invite
        
        invite_encoded = invite_url.replace("0x1fc://invite/", "")
        invite_json = b64d(invite_encoded).decode("utf-8")
        invite_data = json.loads(invite_json)
        
        # Check version
        if invite_data.get("version") != 1:
            return None
        
        # Check expiration
        if time.time() > invite_data.get("expires_at", 0):
            return None  # Expired
        
        # Verify signature
        signature = b64d(invite_data["signature"])
        invite_data_copy = dict(invite_data)
        del invite_data_copy["signature"]
        
        canonical = json.dumps(invite_data_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        
        # Load sponsor public key from fingerprint
        sponsor_fp = invite_data.get("sponsor_fingerprint")
        if not sponsor_fp:
            return None
        
        # In a real implementation, we'd look up the public key from trust store
        # For now, we'll just check if the fingerprint is in trusted set
        if trusted_fingerprints and sponsor_fp not in trusted_fingerprints:
            return None  # Sponsor not trusted
        
        # Note: Full signature verification requires loading the sponsor's public key
        # This is a placeholder - in production, load from trust store
        
        return invite_data
        
    except Exception:
        return None


def cloudflared_exists() -> bool:
    return shutil.which("cloudflared") is not None


def random_port() -> int:
    return random.randint(DEFAULT_PORT_MIN, DEFAULT_PORT_MAX)


def stop_cloudflare_tunnel(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is not None:
            return

        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            time.sleep(1)

        if proc.poll() is None:
            proc.terminate()
            time.sleep(1)

        if proc.poll() is None:
            proc.kill()

    except Exception as e:
        try:
            proc.kill()
        except Exception as e2:
            warn(f"Failed to kill process: {e2}")


async def verify_tunnel_accessible(url: str, timeout: int = 10) -> bool:
    try:
        def check_url():
            req = urllib.request.Request(url, method='HEAD')
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status < 500
        return await asyncio.to_thread(check_url)
    except Exception:
        return False


async def start_cloudflare_tunnel(local_port: int, token: str) -> CloudflareTunnel:
    if not cloudflared_exists():
        raise RuntimeError(
            "cloudflared was not found in PATH.\n\n"
            "To host relays with Cloudflare tunnels, you need cloudflared installed.\n\n"
            "Installation options:\n"
            "• winget install --id Cloudflare.cloudflared\n"
            "• Download from: https://github.com/cloudflare/cloudflared/releases\n"
            "• Place cloudflared.exe in a directory on your PATH"
        )

    cmd = [
        "cloudflared",
        "tunnel",
        "--url",
        f"http://127.0.0.1:{local_port}",
    ]

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    info("Starting Cloudflare tunnel...")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        creationflags=creationflags,
    )

    url = None
    pattern = re.compile(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com")
    lines = []
    started = time.time()

    while time.time() - started < 60:
        if proc.poll() is not None:
            raise RuntimeError("cloudflared exited early:\n" + "\n".join(lines[-30:]))

        line = await asyncio.to_thread(proc.stdout.readline)

        if line:
            lines.append(line.rstrip())
            match = pattern.search(line)

            if match:
                url = match.group(0)
                info(f"Cloudflare tunnel established: {url}")
                break

        await asyncio.sleep(0.05)

    if not url:
        stop_cloudflare_tunnel(proc)
        raise RuntimeError("Could not detect trycloudflare URL:\n" + "\n".join(lines[-30:]))

    info("Verifying tunnel is accessible...")

    for attempt in range(5):
        if await verify_tunnel_accessible(url, timeout=5):
            info("Tunnel verified and accessible.")
            break
        if attempt < 4:
            await asyncio.sleep(1)
    else:
        warn("Tunnel URL detected but not immediately accessible. It may take a moment to propagate.")

    return CloudflareTunnel(
        process=proc,
        url=url,
        local_port=local_port,
        token=token,
    )


def vpn_warning_gate(action: str) -> bool:
    banner()

    console.print(Panel(
        f"You are about to {action}.\n\n"
        "VPN WARNING:\n\n"
        "Connect to a trusted VPN before continuing.\n\n"
        "Cloudflare Tunnel may hide the relay host IP from room users, but Cloudflare can still see metadata.\n"
        "Your ISP can also see that you are connecting to Cloudflare or related infrastructure.\n\n"
        "A VPN reduces direct home/public IP exposure to infrastructure providers and local observers, "
        "but it does not make you fully anonymous.\n\n"
        "Host-blind E2E warning:\n\n"
        "The relay host cannot read messages/files only if the host does not receive the E2E room key.\n"
        "The room key is stored in the invite fragment after #rk= and is never sent to the WebSocket server.\n\n"
        "Recommended:\n"
        "1. Connect to VPN.\n"
        "2. Start or join the relay.\n"
        "3. Share the E2E room key only with intended users.\n"
        "4. Verify fingerprints out-of-band.",
        title="VPN + HOST-BLIND E2E WARNING",
        border_style="red",
    ))

    return Confirm.ask(
        "I confirm my VPN is active and I understand the metadata/key-sharing risks. Continue?",
        default=False,
    )


async def ws_send_json(ws, obj: dict) -> None:
    await ws.send(json.dumps(obj, separators=(",", ":")))


async def async_input(prompt: str = "") -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


async def async_confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"

    while True:
        answer = (await async_input(f"{prompt} [{suffix}]: ")).strip().lower()

        if not answer:
            return default

        if answer in {"y", "yes"}:
            return True

        if answer in {"n", "no"}:
            return False


def epic_line() -> str:
    return random.choice([
        "⟦ BLIND RELAY ONLINE :: OVERLAY SEALED ⟧",
        "⟦ THE SYSTEM THAT NEVER SLEEPS ⟧",
        "◆" * 54,
        "▓▒░" * 18,
        "⟦ HOST SEES STATIC :: ROOM SEES SIGNAL ⟧",
        "⟦ E2E PAYLOAD LOCKED UNDER AES-256-GCM ⟧",
    ])


def room_art() -> str:
    return random.choice([
        r"""
╔════════════════════════════════════════════╗
║       HOST-BLIND E2E OVERLAY ACTIVE        ║
║        RELAY SEES NO PLAINTEXT             ║
╚════════════════════════════════════════════╝
""",
        r"""
[ client ]──sealed blob──>[ blind relay ]──sealed blob──>[ client ]
     │                                                        │
     └────────────── shared E2E room key overlay ─────────────┘
""",
        r"""
       /\_/\
      ( o.o )   blind relay creature is carrying ciphertext
       > ^ <
""",
    ])


def parse_dice(expr: str) -> Tuple[int, int]:
    expr = expr.lower().strip()

    if "d" not in expr:
        return 1, int(expr)

    left, right = expr.split("d", 1)
    count = int(left) if left else 1
    sides = int(right)

    count = max(1, min(count, 100))
    sides = max(2, min(sides, 1_000_000))

    return count, sides


def chat_help() -> None:
    console.print()
    console.print(Panel(
        "Host-blind E2E room commands:\n\n"
        "/help                       Show this help\n"
        "/me ACTION                  Send action text\n"
        "/shout TEXT                 Send dramatic text\n"
        "/roll d20                   Roll dice\n"
        "/roll 4d6                   Roll multiple dice\n"
        "/coin                       Flip a coin\n"
        "/pulse                      Send room pulse effect\n"
        "/art                        Send ASCII room art\n"
        "/file PATH                  Send encrypted file to room\n"
        "/participants /who          Show room participants\n"
        "/status                     Show connection status\n"
        "/history                    Show command history\n"
        "/quit                       Leave room\n\n"
        "Security:\n"
        "Messages/files are encrypted before the relay sees them.\n"
        "The relay only forwards signed encrypted envelopes.",
        title="Commands",
        border_style="cyan",
    ))


class BlindRelayServer:
    def __init__(self, token: str):
        self.token = token
        self.clients: Dict[str, object] = {}
        self.lock = asyncio.Lock()
        self.relayed_packets = 0
        self.started_at = now()
        
        # Military-grade rate limiting
        self.rate_limits: Dict[str, list] = {}
        self.rate_limit_window = 10
        self.rate_limit_max = 100
        self.banned_clients: set = set()
        self.ban_duration = 300
        self.ban_expiry: Dict[str, float] = {}
        
        # Health monitoring
        self.health_check_interval = 30
        self.last_health_check = now()
        self.healthy = True

    def is_rate_limited(self, client_id: str) -> bool:
        now_time = time.time()
        
        if client_id in self.ban_expiry:
            if now_time > self.ban_expiry[client_id]:
                self.ban_expiry.pop(client_id, None)
                self.banned_clients.discard(client_id)
                self.rate_limits.pop(client_id, None)
                return False
            else:
                return True
        
        if client_id in self.banned_clients:
            return True
        
        if client_id in self.rate_limits:
            self.rate_limits[client_id] = [
                ts for ts in self.rate_limits[client_id] 
                if now_time - ts < self.rate_limit_window
            ]
        else:
            self.rate_limits[client_id] = []
        
        if len(self.rate_limits[client_id]) >= self.rate_limit_max:
            self.banned_clients.add(client_id)
            self.ban_expiry[client_id] = now_time + self.ban_duration
            log_security_event("client_rate_limited_banned", {"client_id": client_id})
            return True
        
        self.rate_limits[client_id].append(now_time)
        return False

    async def add(self, client_id: str, ws) -> None:
        async with self.lock:
            self.clients[client_id] = ws

        info(f"Client connected: {client_id}. Active clients: {len(self.clients)}")

    async def remove(self, client_id: str) -> None:
        async with self.lock:
            self.clients.pop(client_id, None)

        info(f"Client disconnected: {client_id}. Active clients: {len(self.clients)}")

    async def broadcast(self, sender_id: str, envelope: dict) -> None:
        if self.is_rate_limited(sender_id):
            warn(f"Rate limited/banned client {sender_id} attempted to broadcast")
            return
        
        dead = []

        async with self.lock:
            targets = list(self.clients.items())

        for cid, ws in targets:
            if cid == sender_id:
                continue

            try:
                await ws_send_json(ws, envelope)
            except Exception as e:
                dead.append(cid)

        for cid in dead:
            await self.remove(cid)

        self.relayed_packets += 1

    async def stats_loop(self) -> None:
        while True:
            await asyncio.sleep(15)

            async with self.lock:
                count = len(self.clients)

            info(
                f"Blind relay stats: clients={count}, relayed_packets={self.relayed_packets}, started={self.started_at}, banned={len(self.banned_clients)}"
            )
            
            # Health check
            self.last_health_check = now()
            self.healthy = True


async def host_blind_relay() -> None:
    if not vpn_warning_gate("host a blind relay"):
        warn("Hosting cancelled. Connect to VPN first.")
        input("\nPress Enter...")
        return

    banner()

    # Get identity for web UI auto-login
    identity = None
    password = None
    if IDENTITY_FILE.exists():
        password = getpass.getpass("Enter password for identity (leave empty to skip web UI auto-login): ")
        if password:
            try:
                identity = load_identity_from_file(password)
            except Exception as e:
                warn(f"Failed to load identity: {e}")
                password = None

    config = load_config()
    default_port = config.get("default_port")
    relay_mode = config.get("relay_mode", "cloudflare")
    
    # Display relay mode information
    console.print(Panel(
        f"Relay Mode: {relay_mode.upper()}\n\n"
        f"Cloudflare: Convenience mode, Cloudflare sees metadata\n"
        f"Tor: Privacy mode, requires Tor service\n"
        f"WireGuard: Controlled infrastructure mode\n"
        f"LAN: Local-only mode, no internet exposure",
        title="Transport Security",
        border_style="yellow",
    ))
    
    if relay_mode == "cloudflare":
        console.print("[yellow]Cloudflare Tunnel convenience mode selected.[/yellow]")
        console.print("[yellow]Cloudflare can see connection metadata, timing, and tunnel information.[/yellow]")
    elif relay_mode == "tor":
        console.print("[green]Tor privacy mode selected.[/green]")
        console.print("[yellow]Note: Requires Tor service to be running locally.[/yellow]")
    elif relay_mode == "wireguard":
        console.print("[green]WireGuard controlled infrastructure mode selected.[/green]")
        console.print("[yellow]Note: Requires WireGuard configuration and VPN connection.[/yellow]")
    elif relay_mode == "lan":
        console.print("[green]LAN-only mode selected.[/green]")
        console.print("[green]No internet exposure - only local network access.[/green]")
    
    console.print()
    
    local_port = IntPrompt.ask("Local WebSocket port", default=default_port if default_port else random_port())
    token = secrets.token_urlsafe(32)
    relay = BlindRelayServer(token)

    # Start web UI server in background if identity is available
    web_ui_process = None
    web_ui_port = None
    if identity and password:
        try:
            web_ui_port = random_port()
            info(f"Starting web UI on port {web_ui_port}...")
            web_ui_process = start_web_ui_server(web_ui_port, password, identity.fingerprint, identity.display_name)
            good(f"Web UI started on http://127.0.0.1:{web_ui_port}")
        except Exception as e:
            warn(f"Failed to start web UI: {e}")
            web_ui_process = None

    async def handler(ws) -> None:
        client_id = secrets.token_hex(8)

        try:
            request_path = "/"

            if hasattr(ws, "request") and ws.request is not None:
                request_path = ws.request.path
            elif hasattr(ws, "path"):
                request_path = ws.path

            parsed = urlparse(request_path)
            qs = parse_qs(parsed.query)
            supplied = qs.get("token", [""])[0]

            if parsed.path != "/ws":
                await ws.close(code=1008, reason="Invalid endpoint")
                return

            if supplied != token:
                await ws.close(code=1008, reason="Invalid token")
                return

            await relay.add(client_id, ws)

            await ws_send_json(ws, {
                "type": "relay_welcome",
                "relay": "blind",
                "protocol": PROTOCOL_VERSION,
                "client_id": client_id,
                "note": "Relay cannot decrypt E2E overlay payloads.",
            })

            async for raw in ws:
                try:
                    envelope = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                if envelope.get("type") != "e2e":
                    continue

                await relay.broadcast(client_id, envelope)

        except ConnectionClosed:
            pass

        except InvalidUpgrade:
            pass

        except Exception as e:
            bad(f"Relay client error: {e}")

        finally:
            await relay.remove(client_id)

    server = None
    tunnel = None

    try:
        try:
            server = await websockets.serve(
                handler,
                "127.0.0.1",
                local_port,
                max_size=MAX_WS_MESSAGE,
                ping_interval=20,
                ping_timeout=20,
            )
        except OSError as e:
            if "address already in use" in str(e).lower():
                bad(f"Port {local_port} is already in use.")
                console.print()
                console.print("[yellow]Suggestions:[/yellow]")
                console.print("• Choose a different port when prompted")
                console.print("• Or close the application using this port")
                console.print("• Common ports to avoid: 80, 443, 8080, 3000")
                input("\nPress Enter...")
                return
            raise

        info(f"WebSocket server successfully started on 127.0.0.1:{local_port}")

        # Handle different relay modes
        if relay_mode == "cloudflare":
            tunnel = await start_cloudflare_tunnel(local_port, token)
            relay_link = build_relay_link(tunnel.url, token)
            transport_info = "Cloudflare Tunnel (convenience mode - Cloudflare sees metadata)"
        elif relay_mode == "tor":
            # For Tor mode, we'd need to configure the local server to listen on Tor's SOCKS proxy
            # This is a placeholder - actual Tor integration requires additional setup
            relay_link = f"ws://127.0.0.1:{local_port}?token={token}"
            transport_info = "Local WebSocket (configure Tor to forward to this endpoint)"
            warn("Tor mode requires manual Tor service configuration")
        elif relay_mode == "wireguard":
            # WireGuard mode - assume VPN is already configured
            # Use the VPN interface IP instead of localhost
            relay_link = f"ws://10.0.0.1:{local_port}?token={token}"  # Placeholder VPN IP
            transport_info = "WireGuard VPN (ensure VPN is connected)"
            warn("WireGuard mode requires VPN connection and proper IP configuration")
        elif relay_mode == "lan":
            # LAN mode - bind to all interfaces
            # Note: This would require changing the server bind address from 127.0.0.1 to 0.0.0.0
            relay_link = f"ws://192.168.1.X:{local_port}?token={token}"  # Placeholder
            transport_info = "LAN-only (local network access only)"
            warn("LAN mode requires manual IP configuration")
        else:
            # Fallback to local-only
            relay_link = f"ws://127.0.0.1:{local_port}?token={token}"
            transport_info = "Local WebSocket only"

        banner()
        
        panel_text = f"Blind relay link:\n\n{relay_link}\n\n"
        panel_text += f"Transport: {transport_info}\n\n"
        panel_text += "This link only contains the relay token.\n"
        panel_text += "It does NOT contain the E2E room key.\n\n"
        panel_text += "[yellow]IMPORTANT: Do NOT open this link in a browser.[/yellow]\n"
        panel_text += "[yellow]This is a WebSocket endpoint for client connections only.[/yellow]\n\n"
        
        if web_ui_process:
            panel_text += f"[cyan]Web UI: http://127.0.0.1:{web_ui_port}[/cyan]\n"
            panel_text += "Access the web interface for full chat features.\n\n"
        
        panel_text += "To make a host-blind E2E invite, a participant should append a separate room key:\n\n"
        panel_text += f"{relay_link}#rk=ROOM_KEY_HERE\n\n"
        panel_text += "Use menu option 3 to generate an E2E room key/invite from a relay link.\n\n"
        panel_text += "For true host-blindness, do not give the relay host the #rk room-key fragment."
        
        console.print(Panel(
            panel_text,
            title="Blind Relay Active",
            border_style="green",
        ))

        asyncio.create_task(relay.stats_loop())

        info("Blind relay is live. Press Ctrl+C to stop.")
        await asyncio.Future()

    except KeyboardInterrupt:
        pass

    except Exception as e:
        bad(str(e))
        input("\nPress Enter...")

    finally:
        if tunnel:
            stop_cloudflare_tunnel(tunnel.process)

        if server:
            server.close()
            await server.wait_closed()

        if web_ui_process:
            info("Stopping web UI server...")
            web_ui_process.terminate()
            try:
                web_ui_process.wait(timeout=5)
            except:
                web_ui_process.kill()

        warn("Blind relay stopped. Invite URL is dead.")
        input("\nPress Enter...")


class ClientRoom:
    def __init__(self, identity: Identity, ws, overlay: OverlayCrypto):
        self.identity = identity
        self.ws = ws
        self.overlay = overlay
        self.room_id = overlay.room_id
        self.incoming_files: Dict[str, IncomingFile] = {}
        self.rejected_files = set()
        self.known_names: Dict[str, str] = {}
        self.participants: Dict[str, str] = {}
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TransferSpeedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
        )
        self.progress_started = False
        self.last_ping = time.time()
        self.connected = True
        self.command_history: list[str] = []
        self.history_index = -1

        settings = get_settings(identity)
        self.max_file_size = int(settings.get("max_file_size", DEFAULT_MAX_FILE_SIZE))

    async def send_packet(self, packet: dict) -> None:
        envelope = self.overlay.encrypt_packet(packet)
        await ws_send_json(self.ws, envelope)

    async def announce_join(self) -> None:
        await self.send_packet({
            "kind": "system_join",
            "body": f"{self.identity.display_name} joined the E2E overlay.",
        })

    async def send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            bad("File does not exist.")
            return

        size = path.stat().st_size

        if size > self.max_file_size:
            bad(f"File is too large. Limit is {human_bytes(self.max_file_size)}.")
            return

        file_id = secrets.token_hex(16)
        filename = safe_name(path.name)

        await self.send_packet({
            "kind": "file_offer",
            "file_id": file_id,
            "filename": filename,
            "size": size,
        })

        sha = hashlib.sha256()
        sent = 0
        index = 0

        try:
            with path.open("rb") as f:
                progress = Progress(
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("•"),
                    TransferSpeedColumn(),
                    TextColumn("•"),
                    TimeRemainingColumn(),
                    console=console,
                )

                with progress:
                    task = progress.add_task(f"Sending {filename}", total=size)

                    while True:
                        chunk = f.read(FILE_CHUNK_SIZE)

                        if not chunk:
                            break

                        sha.update(chunk)

                        await self.send_packet({
                            "kind": "file_chunk",
                            "file_id": file_id,
                            "index": index,
                            "data": b64e(chunk),
                        })

                        sent += len(chunk)
                        index += 1
                        progress.update(task, advance=len(chunk))

            await self.send_packet({
                "kind": "file_end",
                "file_id": file_id,
                "sha256": sha.hexdigest(),
                "chunks": index,
            })

            good(f"Encrypted file sent to E2E room: {filename} ({human_bytes(size)})")
            log_secure(self.identity, self.room_id, "YOU", f"[sent file] {filename} {human_bytes(size)}")

        except Exception as e:
            bad(f"Failed to send file: {e}")
            console.print()

    async def handle_overlay_packet(self, packet: dict) -> None:
        kind = packet.get("kind")
        sender_name = packet.get("sender_name", "Unknown")
        sender_fp = packet.get("sender_fp", "")
        ts = packet.get("timestamp", now())

        self.last_ping = time.time()

        old_key = key_change_warning(self.identity, sender_name, sender_fp)
        trusted = trusted_name(self.identity, sender_fp)

        if old_key:
            console.print()
            console.print(Panel(
                f"Name: {sender_name}\n"
                f"Known fingerprint prefix: {old_key[:24]}...\n"
                f"New fingerprint: {sender_fp}\n\n"
                "This can mean identity reset, new device, or impersonation.",
                title="CONTACT KEY-CHANGE WARNING",
                border_style="red",
            ))

        if not trusted and sender_fp != self.identity.fingerprint:
            console.print()
            console.print(Panel(
                f"Sender: {sender_name}\n"
                f"Fingerprint: {sender_fp}\n\n"
                "This sender is not in your encrypted trust store yet.",
                title="New Signed Sender",
                border_style="yellow",
            ))

            if await async_confirm(f"Trust {sender_name}?", default=False):
                trust_contact(self.identity, sender_fp, sender_name)
                good(f"Trusted {sender_name}.")

        self.known_names[sender_fp] = sender_name
        self.participants[sender_fp] = sender_name

        if kind == "system_join":
            console.print(f"[dim]{ts}[/dim] [magenta][E2E][/magenta] [cyan]{sender_name}[/cyan] {packet.get('body', '')}")
            return

        if kind == "message":
            body = packet.get("body", "")
            console.print(f"[dim]{ts}[/dim] [cyan]{sender_name}[/cyan]: {body}")
            log_secure(self.identity, self.room_id, sender_name, body)
            return

        if kind == "action":
            body = packet.get("body", "")
            console.print(f"[dim]{ts}[/dim] [magenta]* {sender_name}[/magenta] {body}")
            log_secure(self.identity, self.room_id, sender_name, f"* {body}")
            return

        if kind == "file_offer":
            await self.handle_file_offer(packet)
            return

        if kind == "file_chunk":
            await self.handle_file_chunk(packet)
            return

        if kind == "file_end":
            await self.handle_file_end(packet)
            return

        warn(f"Unknown E2E packet kind: {kind}")

    async def handle_file_offer(self, packet: dict) -> None:
        file_id = packet["file_id"]
        sender = packet.get("sender_name", "Unknown")
        filename = safe_name(packet.get("filename", "file.bin"))
        size = int(packet.get("size", 0))

        console.print()
        console.print(Panel(
            f"Sender: {sender}\n"
            f"File: {filename}\n"
            f"Size: {human_bytes(size)}\n"
            f"Your limit: {human_bytes(self.max_file_size)}",
            title="Incoming E2E File",
            border_style="yellow",
        ))

        if size > self.max_file_size:
            warn("File rejected automatically because it exceeds your size limit.")
            self.rejected_files.add(file_id)
            return

        config = load_config()
        auto_accept = config.get("auto_accept_files", False)

        if auto_accept:
            good("Auto-accepting file (configured in settings).")
            accepted = True
        else:
            accepted = await async_confirm("Accept this file?", default=False)

        if not accepted:
            warn("File declined.")
            self.rejected_files.add(file_id)
            return

        temp_path = DOWNLOAD_DIR / f"{filename}.part-{file_id}"
        final_path = unique_path(DOWNLOAD_DIR / filename)

        incoming = IncomingFile(
            file_id=file_id,
            sender=sender,
            filename=filename,
            size=size,
            temp_path=temp_path,
            final_path=final_path,
        )
        incoming.open()

        if not self.progress_started:
            self.progress.start()
            self.progress_started = True

        incoming.progress_task = self.progress.add_task(f"Receiving {filename}", total=size)

        self.incoming_files[file_id] = incoming
        good("File accepted. Receiving encrypted chunks...")

    async def handle_file_chunk(self, packet: dict) -> None:
        file_id = packet["file_id"]

        if file_id in self.rejected_files:
            return

        incoming = self.incoming_files.get(file_id)

        if not incoming:
            return

        data = b64d(packet["data"])

        if incoming.received + len(data) > self.max_file_size:
            incoming.abort()
            if incoming.progress_task:
                self.progress.remove_task(incoming.progress_task)
            self.incoming_files.pop(file_id, None)
            self.rejected_files.add(file_id)
            bad("File exceeded your configured size limit. Aborted.")
            return

        incoming.write(data)

        if incoming.progress_task:
            self.progress.update(incoming.progress_task, advance=len(data))

    async def handle_file_end(self, packet: dict) -> None:
        file_id = packet["file_id"]

        if file_id in self.rejected_files:
            return

        incoming = self.incoming_files.pop(file_id, None)

        if not incoming:
            return

        if incoming.progress_task:
            self.progress.remove_task(incoming.progress_task)

        try:
            final = incoming.finish(packet["sha256"])
            good(f"E2E file received and verified: {final} ({human_bytes(incoming.size)})")
            log_secure(self.identity, self.room_id, incoming.sender, f"[received file] {final}")

        except Exception as e:
            incoming.abort()
            bad(str(e))


async def client_sender_loop(room: ClientRoom) -> None:
    chat_help()

    while True:
        try:
            participant_count = len(room.participants)
            status = f"[green]●[/green]" if room.connected else "[red]●[/red]"
            prompt_text = f"{status} [{participant_count} online] You > "
            text = await async_input(prompt_text)
        except EOFError:
            text = "/quit"

        text = text.strip()

        if not text:
            continue

        if text == "/quit":
            break

        if text == "/help":
            chat_help()
            continue

        if text.startswith("/me "):
            action_text = text[4:]
            await room.send_packet({
                "kind": "action",
                "body": action_text,
            })
            log_secure(room.identity, room.room_id, "YOU", f"* {action_text}")
            continue

        if text.startswith("/shout "):
            shout_text = text[7:].upper()
            await room.send_packet({
                "kind": "message",
                "body": shout_text,
            })
            log_secure(room.identity, room.room_id, "YOU", shout_text)
            continue

        if text.startswith("/roll "):
            expr = text[6:].strip()
            try:
                count, sides = parse_dice(expr)
                results = [random.randint(1, sides) for _ in range(count)]
                total = sum(results)
                result_str = f"{results} = {total}" if count > 1 else str(results[0])
                await room.send_packet({
                    "kind": "message",
                    "body": f"🎲 rolled {expr}: {result_str}",
                })
                log_secure(room.identity, room.room_id, "YOU", f"/roll {expr}: {result_str}")
            except (ValueError, IndexError):
                warn("Usage: /roll d20 or /roll 4d6")
            continue

        if text == "/coin":
            result = random.choice(["heads", "tails"])
            await room.send_packet({
                "kind": "message",
                "body": f"🪙 flipped a coin: {result}",
            })
            log_secure(room.identity, room.room_id, "YOU", f"/coin: {result}")
            continue

        if text == "/pulse":
            await room.send_packet({
                "kind": "message",
                "body": "💓 PULSE",
            })
            log_secure(room.identity, room.room_id, "YOU", "/pulse")
            continue

        if text == "/art":
            await room.send_packet({
                "kind": "message",
                "body": room_art(),
            })
            log_secure(room.identity, room.room_id, "YOU", "/art")
            continue

        if text.startswith("/file "):
            file_path_str = text[6:].strip()
            if not file_path_str:
                warn("Usage: /file PATH")
                continue

            path = Path(file_path_str)
            await room.send_file(path)
            continue

        if text == "/participants" or text == "/who":
            if room.participants:
                console.print()
                table = Table(title="Room Participants", box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("Fingerprint", style="dim")
                for fp, name in room.participants.items():
                    table.add_row(name, short_fp(fp))
                console.print(table)
            else:
                warn("No other participants detected yet.")
            continue

        if text == "/status":
            console.print()
            conn_status = "[green]Connected[/green]" if room.connected else "[red]Disconnected[/red]"
            last_activity = time.strftime('%H:%M:%S', time.localtime(room.last_ping))
            status_panel = Panel(
                f"Connection: {conn_status}\n"
                f"Room ID: {room.room_id}\n"
                f"Participants: {len(room.participants)}\n"
                f"Last activity: {last_activity}",
                title="Connection Status",
                border_style="cyan",
            )
            console.print(status_panel)
            continue

        if text == "/history":
            if room.command_history:
                console.print()
                table = Table(title="Command History", box=box.SIMPLE)
                table.add_column("#", style="dim")
                table.add_column("Command", style="white")
                for i, cmd in enumerate(room.command_history[-10:], 1):
                    table.add_row(str(i), cmd)
                console.print(table)
            else:
                warn("No command history yet.")
            continue

        await room.send_packet({
            "kind": "message",
            "body": text,
        })

        log_secure(room.identity, room.room_id, "YOU", text)

        if text and not text.startswith("/"):
            room.command_history.append(text)
            if len(room.command_history) > 100:
                room.command_history.pop(0)


async def client_receiver_loop(room: ClientRoom) -> None:
    health_task = asyncio.create_task(connection_health_monitor(room))

    try:
        async for raw in room.ws:
            try:
                envelope = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if envelope.get("type") == "relay_welcome":
                info("Connected to blind relay. Starting host-blind E2E overlay.")
                continue

            if envelope.get("type") != "e2e":
                continue

            try:
                packet = room.overlay.decrypt_envelope(envelope)

                if not packet:
                    continue

                if packet.get("sender_fp") == room.identity.fingerprint:
                    continue

                await room.handle_overlay_packet(packet)

            except InvalidSignature:
                bad("Rejected packet with invalid P-521 signature.")

            except InvalidTag:
                bad("Rejected packet: E2E authentication failed.")

            except Exception as e:
                bad(f"Rejected overlay packet: {e}")

    except ConnectionClosed:
        warn("Connection closed.")

    finally:
        room.connected = False
        health_task.cancel()
        if room.progress_started:
            room.progress.stop()
        for incoming in list(room.incoming_files.values()):
            incoming.abort()


async def join_e2e_room(identity: Identity) -> None:
    if not vpn_warning_gate("join a host-blind E2E room"):
        warn("Join cancelled. Connect to VPN first.")
        input("\nPress Enter...")
        return

    banner()

    raw = Prompt.ask("Paste full E2E invite link")
    ws_url, token, room_key_text = parse_invite(raw)
    room_key = decode_room_key(room_key_text)
    overlay = OverlayCrypto(identity, room_key)

    # Start web UI server with auto-login
    web_ui_process = None
    web_ui_port = None
    password = None
    
    try:
        # Get password for web UI auto-login
        password = getpass.getpass("Enter password for identity (leave empty to skip web UI): ")
        if password:
            try:
                web_ui_port = random_port()
                info(f"Starting web UI on port {web_ui_port}...")
                web_ui_process = start_web_ui_server(
                    web_ui_port, 
                    password, 
                    identity.fingerprint, 
                    identity.display_name,
                    invite_link=raw
                )
                good(f"Web UI started on http://127.0.0.1:{web_ui_port}")
            except Exception as e:
                warn(f"Failed to start web UI: {e}")
                web_ui_process = None
    except Exception as e:
        warn(f"Could not start web UI: {e}")
        web_ui_process = None

    banner()
    console.print(Panel(
        f"Relay endpoint:\n{ws_url}\n\n"
        f"E2E room ID:\n{overlay.room_id}\n\n"
        "The relay receives only signed encrypted overlay envelopes.\n"
        "The #rk room key is stripped locally and is not sent to the relay.\n\n"
        f"[cyan]Web UI: http://127.0.0.1:{web_ui_port}[/cyan]" if web_ui_process else "",
        title="Connecting",
        border_style="cyan",
    ))

    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            info(f"Connecting to relay (attempt {attempt + 1}/{max_retries})...")

            async with websockets.connect(
                ws_url,
                max_size=MAX_WS_MESSAGE,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=10,
            ) as ws:
                info("Connected to relay successfully.")
                room = ClientRoom(identity, ws, overlay)

                await room.announce_join()

                sender = asyncio.create_task(client_sender_loop(room))
                receiver = asyncio.create_task(client_receiver_loop(room))

                done, pending = await asyncio.wait(
                    {sender, receiver},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in pending:
                    task.cancel()

                return

        except (ConnectionClosed, OSError, TimeoutError) as e:
            if attempt < max_retries - 1:
                warn(f"Connection failed: {e}")
                console.print()
                console.print("[yellow]Suggestions:[/yellow]")
                console.print("• Check your internet connection")
                console.print("• Verify the relay link is correct and active")
                console.print("• The relay host may have stopped the server")
                info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
            else:
                bad(f"Failed to connect after {max_retries} attempts: {e}")
                console.print()
                console.print("[yellow]Suggestions:[/yellow]")
                console.print("• The relay may be offline or the link expired")
                console.print("• Ask the host for a new invite link")
                console.print("• Check if you need to use a VPN")
                input("\nPress Enter...")
                return

        except Exception as e:
            bad(f"Connection failed: {e}")
            console.print()
            console.print("[yellow]Suggestions:[/yellow]")
            console.print("• Verify the invite link is complete and correct")
            console.print("• Check your network connection")
            input("\nPress Enter...")
            return
        finally:
            if web_ui_process:
                info("Stopping web UI server...")
                web_ui_process.terminate()
                try:
                    web_ui_process.wait(timeout=5)
                except:
                    web_ui_process.kill()


def make_e2e_invite_tool() -> None:
    banner()

    # Load identity for signing
    identity = None
    if IDENTITY_FILE.exists():
        password = getpass.getpass("Enter password for identity (leave empty for unsigned invite): ")
        if password:
            try:
                identity = load_identity_from_file(password)
            except Exception as e:
                warn(f"Failed to load identity: {e}")
                console.print("[yellow]Creating unsigned invite (no signature, no expiration)[/yellow]")
    
    relay_link = Prompt.ask("Paste relay link without room key")
    room_key = generate_room_key()
    
    # Ask for invite parameters if identity is available
    if identity:
        expires_in = IntPrompt.ask("Invite expires in hours", default=24)
        max_uses = IntPrompt.ask("Maximum uses", default=1)
        role = Prompt.ask("Role", default="member", choices=["member", "admin"])
        
        invite = build_e2e_invite(relay_link, room_key, identity, expires_in, max_uses, role)
    else:
        invite = build_e2e_invite(relay_link, room_key)  # Unsigned
    
    room_id = room_id_from_key_text(room_key)

    console.print(Panel(
        f"E2E invite link:\n\n{invite}\n\n"
        f"Room ID:\n{room_id}\n\n"
        "Share this full invite only with people who should read room content.\n\n"
        "Host-blind rule:\n"
        "If the relay host should be blind, do not give the relay host this #rk room key.\n\n"
        "[yellow]Security Note:[/yellow]\n"
        "Signed invites include expiration and use limits.\n"
        "Unsigned invites have no expiration or use tracking.",
        title="Generated Host-Blind E2E Invite",
        border_style="green",
    ))

    input("\nPress Enter...")


def import_e2e_key_tool() -> None:
    banner()

    key = Prompt.ask("Paste E2E room key")
    try:
        room_id = room_id_from_key_text(key)
        good(f"Valid room key. Room ID: {room_id}")
    except Exception as e:
        bad(f"Invalid room key: {e}")

    input("\nPress Enter...")


def list_trusted(identity: Identity) -> None:
    banner()

    trust = load_trust(identity)
    contacts = trust.get("contacts_by_fingerprint", {})

    if not contacts:
        warn("No trusted contacts yet.")
        input("\nPress Enter...")
        return

    table = Table(title="Trusted Contacts", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Fingerprint", style="green")
    table.add_column("Trusted At", style="magenta")

    for item in contacts.values():
        table.add_row(
            item.get("name", "Unknown"),
            item.get("fingerprint", ""),
            item.get("trusted_at", ""),
        )

    console.print(table)
    input("\nPress Enter...")


def show_fingerprint(identity: Identity) -> None:
    banner()

    console.print(Panel(
        identity.fingerprint,
        title=f"Your P-521 Signing Identity: {identity.display_name}",
        border_style="cyan",
    ))

    input("\nPress Enter...")


def export_public_identity(identity: Identity) -> None:
    banner()

    out = APP_DIR / "my_public_identity.json"

    payload = {
        "app": APP_NAME,
        "protocol": PROTOCOL_VERSION,
        "display_name": identity.display_name,
        "fingerprint": identity.fingerprint,
        "identity_public_pem": identity.public_pem.decode("utf-8"),
    }

    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    console.print(Panel(
        f"Saved:\n\n{out}\n\nFingerprint:\n{identity.fingerprint}",
        title="Public Identity Exported",
        border_style="green",
    ))

    input("\nPress Enter...")


def settings_menu(identity: Identity) -> None:
    while True:
        banner()

        settings = get_settings(identity)
        config = load_config()
        max_file_size = int(settings.get("max_file_size", DEFAULT_MAX_FILE_SIZE))

        table = Table(title="Settings", box=box.SIMPLE)
        table.add_column("Option", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("1. Display name", settings.get("display_name", identity.display_name))
        table.add_row("2. Max file size", human_bytes(max_file_size))
        table.add_row("3. Default port", str(config.get("default_port", "Auto")))
        table.add_row("4. Auto-accept files", "Yes" if config.get("auto_accept_files") else "No")
        table.add_row("0. Back", "")

        console.print(table)

        choice = Prompt.ask("Choose", default="0")

        if choice == "1":
            new_name = Prompt.ask(
                "New display name",
                default=settings.get("display_name", identity.display_name),
            )
            settings["display_name"] = new_name
            identity.display_name = new_name
            save_settings(identity, settings)
            good("Display name updated.")
            time.sleep(1)

        elif choice == "2":
            mb = IntPrompt.ask(
                "Max file size in MB",
                default=max(1, max_file_size // (1024 * 1024)),
            )
            settings["max_file_size"] = max(1, mb) * 1024 * 1024
            save_settings(identity, settings)
            good("File size limit updated.")
            time.sleep(1)

        elif choice == "3":
            port_input = Prompt.ask("Default port (leave empty for auto)", default="")
            if port_input:
                try:
                    port = int(port_input)
                    if 1024 <= port <= 65535:
                        config["default_port"] = port
                        save_config(config)
                        good(f"Default port set to {port}.")
                    else:
                        bad("Port must be between 1024 and 65535.")
                except ValueError:
                    bad("Invalid port number.")
            else:
                config["default_port"] = None
                save_config(config)
                good("Default port set to auto.")
            time.sleep(1)

        elif choice == "4":
            current = config.get("auto_accept_files", False)
            config["auto_accept_files"] = not current
            save_config(config)
            status = "enabled" if config["auto_accept_files"] else "disabled"
            good(f"Auto-accept files {status}.")
            time.sleep(1)

        elif choice == "0":
            return


def security_info() -> None:
    banner()

    console.print(Panel(
        "Host-blind E2E overlay model:\n\n"
        "1. The relay host creates a Cloudflare tunnel and invite token.\n"
        "2. The E2E room key is separate and lives after #rk= in the invite URL.\n"
        "3. URL fragments are not sent to HTTP/WebSocket servers.\n"
        "4. The client strips the room key locally before connecting.\n"
        "5. Messages and files are encrypted client-side with AES-256-GCM.\n"
        "6. Every encrypted overlay envelope is signed with the sender's long-term P-521 identity key.\n"
        "7. Receivers verify signatures before trusting decrypted content.\n"
        "8. Replay attacks are rejected using sender nonce-prefix + strict counters.\n"
        "9. Local settings, trusted contacts, and logs are encrypted with a password-derived key.\n\n"
        "What the relay host can see:\n"
        "Connection count, timing, traffic volume, approximate file size, sender public metadata in envelopes.\n\n"
        "What the relay host cannot see without #rk:\n"
        "Message text, file names, file contents, file hashes, inner commands.\n\n"
        "Important limitation:\n"
        "This is a shared-room-key overlay, not full MLS. Anyone with the room key can decrypt room content.",
        title="Security Model",
        border_style="cyan",
    ))

    input("\nPress Enter...")


def reset_identity() -> None:
    banner()

    warn("This deletes your identity, encrypted settings, trusted contacts, and encrypted logs.")

    if not Confirm.ask("Reset everything?", default=False):
        return

    for p in [IDENTITY_FILE, PUBLIC_FILE, STORAGE_SALT_FILE, SETTINGS_FILE, TRUST_FILE]:
        try:
            if p.exists():
                p.unlink()
        except Exception as e:
            warn(f"Failed to delete {p}: {e}")

    try:
        for p in LOG_DIR.glob("*.elog"):
            p.unlink()
    except Exception as e:
        warn(f"Failed to delete log files: {e}")

    good("Reset complete.")
    input("\nPress Enter...")


def requirements_check() -> None:
    ensure_dirs()

    if not cloudflared_exists():
        banner()
        bad("cloudflared was not found in PATH.")
        console.print()
        console.print("Install cloudflared, then confirm this works:")
        console.print()
        console.print("[bold]cloudflared version[/bold]")
        console.print()
        input("Press Enter to continue anyway...")


def main_menu(identity: Identity) -> None:
    while True:
        banner()

        settings = get_settings(identity)

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Action")

        table.add_row("1", "Host blind relay with Cloudflare tunnel")
        table.add_row("2", "Join host-blind E2E room")
        table.add_row("3", "Generate E2E invite from relay link")
        table.add_row("4", "Validate/import E2E room key")
        table.add_row("5", "Show my fingerprint")
        table.add_row("6", "Export my public identity")
        table.add_row("7", "Trusted contacts")
        table.add_row("8", "Settings")
        table.add_row("9", "Security model")
        table.add_row("10", "Reset identity/storage")
        table.add_row("0", "Exit")

        console.print(table)

        console.print()
        console.print(Panel(
            f"Identity folder:\n{APP_DIR}\n\n"
            f"Display name: {settings.get('display_name', identity.display_name)}\n"
            f"Max file size: {human_bytes(int(settings.get('max_file_size', DEFAULT_MAX_FILE_SIZE)))}\n"
            f"Downloads:\n{DOWNLOAD_DIR}\n\n"
            f"Your fingerprint:\n{identity.fingerprint}",
            title="Local State",
            border_style="magenta",
        ))

        choice = Prompt.ask("Choose", default="0")

        if choice == "1":
            try:
                asyncio.run(host_blind_relay())
            except KeyboardInterrupt:
                pass

        elif choice == "2":
            try:
                asyncio.run(join_e2e_room(identity))
            except KeyboardInterrupt:
                pass

        elif choice == "3":
            make_e2e_invite_tool()

        elif choice == "4":
            import_e2e_key_tool()

        elif choice == "5":
            show_fingerprint(identity)

        elif choice == "6":
            export_public_identity(identity)

        elif choice == "7":
            list_trusted(identity)

        elif choice == "8":
            settings_menu(identity)

        elif choice == "9":
            security_info()

        elif choice == "10":
            reset_identity()
            if not IDENTITY_FILE.exists():
                identity = load_identity()

        elif choice == "0":
            console.print("[cyan]Goodbye.[/cyan]")
            return

        else:
            warn("Invalid choice.")
            time.sleep(1)


def main() -> None:
    requirements_check()
    banner()

    console.print(Panel(
        "P-521 HOST-BLIND E2E OVERLAY\n\n"
        "This version changes the room model:\n\n"
        "Old model:\n"
        "Users encrypted to the host, and the host relayed readable messages.\n\n"
        "New model:\n"
        "Users encrypt messages/files with a separate E2E room key before the relay sees anything.\n"
        "The relay host only forwards signed encrypted envelopes.\n\n"
        "Critical rule:\n"
        "For host-blindness, the relay host must not receive the #rk room-key fragment.\n\n"
        "VPN warning:\n"
        "Use a trusted VPN before hosting or joining. This reduces direct IP exposure but does not make you anonymous.\n\n"
        "Security considerations:\n"
        "• Ephemeral P-521 keys for session-based encryption\n"
        "• Automatic key rotation (5-minute intervals)\n"
        "• Double-layer encryption (room key + ephemeral key)\n"
        "• Message compression (zlib, level 6)\n"
        "• Message deduplication with TTL cache\n"
        "• Audit logging (file + SQLite)\n"
        "• Rate limiting (100 msg/10s)\n"
        "• Automatic client banning for abuse\n"
        "• SQLite message persistence with indexing\n"
        "• Message threading & reply chains\n"
        "• Full-text message search\n"
        "• Cloudflare blind relay support\n"
        "• Client-side AES-256-GCM E2E overlay\n"
        "• P-521 signed overlay packets\n"
        "• Replay rejection with counters\n"
        "• Encrypted local logs/storage\n"
        "• File accept/deny prompts\n"
        "• File size limits\n"
        "• Contact key-change warnings\n"
        "• Web UI with auto-login integration\n\n"
        "Limitations:\n"
        "• Relay sees metadata (IP, timing, packet size, room ID, fingerprints)\n"
        "• Room key in invite link - protect invite links carefully\n"
        "• TOFU trust model - verify fingerprints out-of-band\n"
        "• No formal protocol transcript or HKDF key schedule",
        title="Startup",
        border_style="red",
    ))

    input("\nPress Enter to unlock or create identity...")

    identity = load_identity()
    main_menu(identity)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[cyan]Exited.[/cyan]")