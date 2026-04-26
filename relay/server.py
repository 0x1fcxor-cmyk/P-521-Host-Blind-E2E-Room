"""
Relay server module - WebSocket blind relay implementation
"""

import asyncio
import time
import logging
from typing import Dict
import json
import websockets

from core.constants import console, PROTOCOL_VERSION

logger = logging.getLogger(__name__)

__all__ = [
    'BlindRelayServer',
    'now',
    'ws_send_json',
    'info',
    'warn',
    'log_security_event',
    'RelayError',
    'RateLimitExceededError'
]


class RelayError(Exception):
    """Base exception for relay errors"""
    pass


class RateLimitExceededError(RelayError):
    """Raised when client exceeds rate limit"""
    pass


def now() -> int:
    """Get current timestamp"""
    return int(time.time())


async def ws_send_json(ws, data: dict) -> None:
    """
    Send JSON data over WebSocket
    
    Args:
        ws: WebSocket connection
        data: Dictionary to send as JSON
    
    Raises:
        RelayError: If sending fails
    """
    if not data:
        raise ValueError("Data cannot be empty")
    
    try:
        await ws.send(json.dumps(data))
    except Exception as e:
        logger.error(f"Failed to send WebSocket message: {e}")
        raise RelayError(f"Failed to send message: {e}") from e


def info(msg: str) -> None:
    """Log info message"""
    console.print(f"[cyan][INFO][/cyan] {msg}")
    logger.info(msg)


def warn(msg: str) -> None:
    """Log warning message"""
    console.print(f"[yellow][WARN][/yellow] {msg}")
    logger.warning(msg)


def log_security_event(event_type: str, details: dict) -> None:
    """
    Log a security event
    
    Args:
        event_type: Type of security event
        details: Event details dictionary
    """
    info(f"[SECURITY] {event_type}: {details}")
    logger.warning(f"Security event: {event_type} - {details}")


class BlindRelayServer:
    """Blind relay server that cannot decrypt E2E content"""

    def __init__(self, token: str):
        """
        Initialize blind relay server
        
        Args:
            token: Authentication token for relay access
        
        Raises:
            ValueError: If token is empty
        """
        if not token:
            raise ValueError("Token cannot be empty")
        
        self.token = token
        self.clients: Dict[str, object] = {}
        self.rate_limits: Dict[str, list] = {}
        self.max_clients = 100
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max = 100  # messages per window
        self.relayed_packets = 0
        self.started_at = now()
        self.healthy = True
        self.last_health_check = now()
        
        logger.info(f"BlindRelayServer initialized with token {token[:8]}...")

    def health_check(self) -> dict:
        """
        Perform health check and return status
        
        Returns:
            Dictionary with health status metrics
        """
        self.last_health_check = now()
        
        return {
            "healthy": self.healthy,
            "clients": len(self.clients),
            "relayed_packets": self.relayed_packets,
            "uptime_seconds": now() - self.started_at,
            "last_health_check": self.last_health_check,
            "max_clients": self.max_clients,
            "rate_limit_window": self.rate_limit_window,
            "rate_limit_max": self.rate_limit_max,
        }

    async def add(self, client_id: str, ws) -> None:
        """
        Add a client to the relay
        
        Args:
            client_id: Unique client identifier
            ws: WebSocket connection
        
        Raises:
            RelayError: If server is full
        """
        if not client_id:
            raise ValueError("Client ID cannot be empty")
        
        if len(self.clients) >= self.max_clients:
            try:
                await ws.close(code=1013, reason="Server full")
            except Exception as e:
                logger.error(f"Failed to close WebSocket: {e}")
            raise RelayError("Server is at maximum capacity")
        
        try:
            self.clients[client_id] = ws
            self.rate_limits[client_id] = []
            info(f"Client {client_id} connected. Total: {len(self.clients)}")
            logger.info(f"Client {client_id} connected")
        except Exception as e:
            logger.error(f"Failed to add client {client_id}: {e}")
            raise RelayError(f"Failed to add client: {e}") from e

        info(f"Client connected: {client_id}. Active clients: {len(self.clients)}")

    async def remove(self, client_id: str) -> None:
        """
        Remove a client from the relay
        
        Args:
            client_id: Client identifier to remove
        """
        if client_id in self.clients:
            try:
                del self.clients[client_id]
                if client_id in self.rate_limits:
                    del self.rate_limits[client_id]
                info(f"Client {client_id} disconnected. Total: {len(self.clients)}")
                logger.info(f"Client {client_id} disconnected")
            except Exception as e:
                logger.error(f"Failed to remove client {client_id}: {e}")

    async def broadcast(self, sender_id: str, envelope: dict) -> None:
        """
        Broadcast an envelope to all clients except sender
        
        Args:
            sender_id: Sender client identifier
            envelope: Envelope dictionary to broadcast
        
        Raises:
            RelayError: If broadcasting fails
        """
        if not envelope:
            raise ValueError("Envelope cannot be empty")
        
        if sender_id not in self.clients:
            logger.warning(f"Broadcast from unknown sender: {sender_id}")
            return

        sender = self.clients[sender_id]
        data = json.dumps(envelope)
        
        failed_clients = []

        for client_id, ws in self.clients.items():
            if client_id == sender_id:
                continue

            try:
                await ws.send(data)
            except Exception as e:
                logger.error(f"Failed to send to client {client_id}: {e}")
                failed_clients.append(client_id)

        # Remove failed clients
        for client_id in failed_clients:
            await self.remove(client_id)
        
        if failed_clients:
            logger.warning(f"Removed {len(failed_clients)} failed clients during broadcast")
        
        self.relayed_packets += 1

    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if client is within rate limits
        
        Args:
            client_id: Client identifier
        
        Returns:
            True if within limits, False otherwise
        
        Raises:
            RateLimitExceededError: If client exceeds rate limit
        """
        if client_id not in self.rate_limits:
            return True

        now_time = now()
        window_start = now_time - self.rate_limit_window

        # Clean old entries
        self.rate_limits[client_id] = [
            ts for ts in self.rate_limits[client_id]
            if ts > window_start
        ]

        if len(self.rate_limits[client_id]) >= self.rate_limit_max:
            logger.warning(f"Rate limit exceeded for client {client_id}")
            raise RateLimitExceededError(f"Rate limit exceeded: {len(self.rate_limits[client_id])} messages per {self.rate_limit_window}s")

        return True

    def record_message(self, client_id: str) -> None:
        """
        Record a message for rate limiting
        
        Args:
            client_id: Client identifier
        """
        if client_id not in self.rate_limits:
            self.rate_limits[client_id] = []

        self.rate_limits[client_id].append(now())
