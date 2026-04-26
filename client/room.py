"""
Client room module - Client-side room implementation for E2E messaging
"""

import hashlib
import random
import secrets
import time
import logging
from pathlib import Path
from typing import Dict, Optional
from contextlib import asynccontextmanager
from rich.progress import Progress, TextColumn, BarColumn, TransferSpeedColumn, TimeRemainingColumn
from rich.console import Console
from cryptography.exceptions import InvalidSignature, InvalidTag

from core.constants import DEFAULT_MAX_FILE_SIZE, FILE_CHUNK_SIZE, console
from identity.keys import Identity
from identity.trust import get_settings, trusted_name, trust_contact
from protocol.envelopes import OverlayCrypto, IncomingFile

logger = logging.getLogger(__name__)

__all__ = [
    'ClientRoom',
    'human_bytes',
    'safe_name',
    'b64e',
    'ws_send_json',
    'info',
    'good',
    'bad',
    'warn'
]

console = Console()


def human_bytes(n: int) -> str:
    """Convert bytes to human-readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def safe_name(name: str) -> str:
    """Sanitize filename for safe storage"""
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(c if c in keep else "_" for c in name)


def b64e(x: bytes) -> str:
    """Base64 encode"""
    import base64
    return base64.b64encode(x).decode("utf-8")


async def ws_send_json(ws, data: dict) -> None:
    """Send JSON data over WebSocket"""
    import json
    await ws.send(json.dumps(data))


def info(msg: str) -> None:
    """Log info message"""
    console.print(f"[cyan][INFO][/cyan] {msg}")


def good(msg: str) -> None:
    """Log success message"""
    console.print(f"[green][OK][/green] {msg}")


def bad(msg: str) -> None:
    """Log error message"""
    console.print(f"[red][ERROR][/red] {msg}")


def warn(msg: str) -> None:
    """Log warning message"""
    console.print(f"[yellow][WARN][/yellow] {msg}")


class ClientRoom:
    """Client-side room implementation for E2E messaging"""
    
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
        
        logger.info(f"ClientRoom initialized for room {self.room_id}")

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup resources"""
        await self.cleanup()
        if exc_type:
            logger.error(f"ClientRoom exited with exception: {exc_type}: {exc_val}")
        return False

    async def cleanup(self) -> None:
        """Clean up resources"""
        logger.info(f"Cleaning up ClientRoom for room {self.room_id}")
        
        # Abort all incoming file transfers
        for file_id, incoming_file in self.incoming_files.items():
            try:
                incoming_file.abort()
                logger.debug(f"Aborted file transfer: {file_id}")
            except Exception as e:
                logger.error(f"Failed to abort file {file_id}: {e}")
        
        self.incoming_files.clear()
        self.rejected_files.clear()
        
        # Close WebSocket connection if still open
        if self.ws and self.connected:
            try:
                await self.ws.close()
                logger.info("WebSocket connection closed")
            except Exception as e:
                logger.error(f"Failed to close WebSocket: {e}")
        
        self.connected = False

    async def send_packet(self, packet: dict) -> None:
        """Encrypt and send a packet to the room"""
        envelope = self.overlay.encrypt_packet(packet)
        await ws_send_json(self.ws, envelope)

    async def announce_join(self) -> None:
        """Announce that this client has joined the room"""
        await self.send_packet({
            "kind": "system_join",
            "body": f"{self.identity.display_name} joined the E2E overlay.",
        })

    async def send_file(self, path: Path) -> None:
        """Send a file to the room"""
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
            logger.info(f"File sent: {filename} ({human_bytes(size)})")

        except Exception as e:
            bad(f"Failed to send file: {e}")
            logger.error(f"Failed to send file {filename}: {e}")
            console.print()

    async def handle_overlay_packet(self, packet: dict) -> None:
        """Handle an incoming overlay packet"""
        kind = packet.get("kind")
        sender_name = packet.get("sender_name", "Unknown")
        sender_fp = packet.get("sender_fp", "")
        ts = packet.get("timestamp", int(time.time()))

        self.last_ping = time.time()

        trusted = trusted_name(self.identity, sender_fp)

        if not trusted and sender_fp != self.identity.fingerprint:
            console.print()
            console.print(f"[yellow]New signed sender: {sender_name} ({sender_fp})[/yellow]")
            # Note: In a full implementation, we'd ask for confirmation here

        self.known_names[sender_fp] = sender_name
        self.participants[sender_fp] = sender_name

        if kind == "message":
            body = packet.get("body", "")
            console.print(f"[cyan]{sender_name}:[/cyan] {body}")

        elif kind == "action":
            body = packet.get("body", "")
            console.print(f"[cyan]* {sender_name}[/cyan] {body}")

        elif kind == "system_join":
            body = packet.get("body", "")
            console.print(f"[green][SYSTEM][/green] {body}")

        elif kind == "file_offer":
            file_id = packet.get("file_id")
            filename = packet.get("filename")
            size = packet.get("size")
            console.print(f"[yellow]{sender_name} offers file:[/yellow] {filename} ({human_bytes(size)})")
            # Note: In a full implementation, we'd handle file acceptance/rejection

        elif kind == "file_chunk":
            # Handle file chunk
            file_id = packet.get("file_id")
            index = packet.get("index")
            data = packet.get("data")
            # Note: In a full implementation, we'd assemble file chunks

        elif kind == "file_end":
            # Handle file end
            file_id = packet.get("file_id")
            sha256 = packet.get("sha256")
            chunks = packet.get("chunks")
            # Note: In a full implementation, we'd finalize the file

    def cleanup(self) -> None:
        """Clean up resources"""
        self.connected = False
        if self.progress_started:
            self.progress.stop()
        for incoming in list(self.incoming_files.values()):
            incoming.abort()
