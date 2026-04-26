"""
Cloudflare transport module - Cloudflare tunnel integration
"""

import asyncio
import os
import random
import re
import secrets
import shutil
import subprocess
import logging
from dataclasses import dataclass
from typing import Tuple
from urllib.parse import urlparse

import aiohttp

from core.constants import DEFAULT_PORT_MIN, DEFAULT_PORT_MAX, console

logger = logging.getLogger(__name__)

__all__ = [
    'CloudflareTunnel',
    'cloudflared_exists',
    'random_port',
    'strip_fragment',
    'parse_invite',
    'build_relay_link',
    'verify_tunnel_accessible',
    'stop_cloudflare_tunnel',
    'start_cloudflare_tunnel',
    'info',
    'warn',
    'CloudflareError',
    'TunnelStartError',
    'TunnelNotFoundError'
]


class CloudflareError(Exception):
    """Base exception for Cloudflare tunnel errors"""
    pass


class TunnelStartError(CloudflareError):
    """Raised when tunnel fails to start"""
    pass


class TunnelNotFoundError(CloudflareError):
    """Raised when cloudflared binary is not found"""
    pass


def info(msg: str) -> None:
    """Log info message"""
    console.print(f"[cyan][INFO][/cyan] {msg}")
    logger.info(msg)


def warn(msg: str) -> None:
    """Log warning message"""
    console.print(f"[yellow][WARN][/yellow] {msg}")
    logger.warning(msg)


@dataclass
class CloudflareTunnel:
    """Cloudflare tunnel process state"""
    process: subprocess.Popen
    port: int
    url: str

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - stop tunnel"""
        stop_cloudflare_tunnel(self)
        if exc_type:
            logger.error(f"CloudflareTunnel exited with exception: {exc_type}: {exc_val}")
        return False


def cloudflared_exists() -> bool:
    """
    Check if cloudflared binary exists
    
    Returns:
        True if cloudflared is found in PATH, False otherwise
    """
    return shutil.which("cloudflared") is not None


def random_port() -> int:
    """
    Generate a random port in the default range
    
    Returns:
        Random port number between DEFAULT_PORT_MIN and DEFAULT_PORT_MAX
    """
    return random.randint(DEFAULT_PORT_MIN, DEFAULT_PORT_MAX)


def strip_fragment(url: str) -> str:
    """
    Remove fragment from URL
    
    Args:
        url: URL string
    
    Returns:
        URL without fragment
    
    Raises:
        ValueError: If URL is invalid
    """
    if not url:
        raise ValueError("URL cannot be empty")
    
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception as e:
        logger.error(f"Failed to parse URL: {e}")
        raise ValueError(f"Invalid URL: {e}") from e


def parse_invite(invite_link: str) -> Tuple[str, str, str]:
    """
    Parse invite link into components
    
    Args:
        invite_link: Full invite link with token and room key
    
    Returns:
        Tuple of (ws_url, token, room_key)
    
    Raises:
        ValueError: If invite link format is invalid
    """
    if not invite_link:
        raise ValueError("Invite link cannot be empty")
    
    try:
        stripped = strip_fragment(invite_link)
        parts = stripped.split("#rk=")
        
        if len(parts) != 2:
            raise ValueError("Invalid invite link format")
        
        ws_url = parts[0]
        token_part = parts[1].split("&")[0]
        room_key_part = parts[1].split("&rk=")[1] if "&rk=" in parts[1] else ""
        
        if not ws_url or not token_part:
            raise ValueError("Missing required components in invite link")
        
        return ws_url, token_part, room_key_part
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"Failed to parse invite link: {e}")
        raise ValueError(f"Failed to parse invite link: {e}") from e


def build_relay_link(ws_url: str, token: str) -> str:
    """
    Build relay link from WebSocket URL and token
    
    Args:
        ws_url: WebSocket URL
        token: Authentication token
    
    Returns:
        Full relay link with token parameter
    
    Raises:
        ValueError: If ws_url or token is empty
    """
    if not ws_url:
        raise ValueError("WebSocket URL cannot be empty")
    
    if not token:
        raise ValueError("Token cannot be empty")
    
    return f"{ws_url}?token={token}"


async def verify_tunnel_accessible(url: str, timeout: int = 10) -> bool:
    """
    Verify if tunnel is accessible
    
    Args:
        url: Tunnel URL to check
        timeout: Request timeout in seconds
    
    Returns:
        True if accessible, False otherwise
    """
    if not url:
        logger.warning("URL is empty, cannot verify tunnel")
        return False
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as resp:
                accessible = resp.status == 200
                logger.info(f"Tunnel accessibility check: {accessible}")
                return accessible
    except asyncio.TimeoutError:
        logger.warning(f"Tunnel verification timed out: {url}")
        return False
    except Exception as e:
        logger.error(f"Tunnel verification failed: {e}")
        return False


def stop_cloudflare_tunnel(tunnel: CloudflareTunnel) -> None:
    """
    Stop a Cloudflare tunnel
    
    Args:
        tunnel: CloudflareTunnel object to stop
    
    Raises:
        CloudflareError: If stopping fails
    """
    if not tunnel:
        logger.warning("Tunnel is None, nothing to stop")
        return
    
    if not tunnel.process:
        logger.warning("Tunnel process is None, nothing to stop")
        return
    
    try:
        tunnel.process.terminate()
        try:
            tunnel.process.wait(timeout=5)
            logger.info(f"Tunnel stopped on port {tunnel.port}")
        except subprocess.TimeoutExpired:
            logger.warning(f"Tunnel did not terminate gracefully, killing")
            tunnel.process.kill()
            tunnel.process.wait()
            logger.info(f"Tunnel killed on port {tunnel.port}")
    except Exception as e:
        logger.error(f"Failed to stop tunnel: {e}")
        raise CloudflareError(f"Failed to stop tunnel: {e}") from e


async def start_cloudflare_tunnel(port: int) -> CloudflareTunnel:
    """
    Start a Cloudflare tunnel on the specified port
    
    Args:
        port: Local port to tunnel
    
    Returns:
        CloudflareTunnel object with process and URL
    
    Raises:
        TunnelNotFoundError: If cloudflared is not installed
        TunnelStartError: If tunnel fails to start
    """
    if not cloudflared_exists():
        error_msg = "cloudflared not found. Install from https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/"
        logger.error(error_msg)
        raise TunnelNotFoundError(error_msg)
    
    if port < 1024 or port > 65535:
        raise ValueError(f"Invalid port: {port} (must be 1024-65535)")

    url = f"https://trycloudflare.com/{secrets.token_urlsafe(16)}"
    
    try:
        process = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"ws://127.0.0.1:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        logger.info(f"Starting cloudflared tunnel on port {port}")
        
        # Wait for tunnel to be ready
        await asyncio.sleep(3)
        
        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            error_msg = stderr.decode() if stderr else "Unknown error"
            logger.error(f"cloudflared process exited: {error_msg}")
            raise TunnelStartError(f"cloudflared failed to start: {error_msg}")
        
        logger.info(f"Cloudflare tunnel started successfully on port {port}")
        
        return CloudflareTunnel(process=process, port=port, url=url)
    except (TunnelNotFoundError, TunnelStartError):
        raise
    except Exception as e:
        logger.error(f"Failed to start tunnel: {e}")
        raise TunnelStartError(f"Failed to start tunnel: {e}") from e
