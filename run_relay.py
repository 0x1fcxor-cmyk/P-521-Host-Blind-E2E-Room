#!/usr/bin/env python3
"""
Portable WebSocket Relay Server for P-521 Host-Blind E2E Room

This script runs a standalone blind relay server that clients can connect to.
The relay cannot decrypt any E2E encrypted content - it only relays messages.

Usage:
    python run_relay.py --token YOUR_SECRET_TOKEN --port 8080

    Or generate a random token:
    python run_relay.py --generate-token

    Or run with default settings:
    python run_relay.py
"""

import asyncio
import argparse
import secrets
import sys
import os
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from relay.server import BlindRelayServer, info, warn, log_security_event
from core.constants import console, PROTOCOL_VERSION


def generate_token() -> str:
    """Generate a secure random token for relay authentication"""
    return secrets.token_urlsafe(32)


async def handle_client(relay: BlindRelayServer, client_id: str, ws, path: str):
    """
    Handle a client connection
    
    Args:
        relay: BlindRelayServer instance
        client_id: Unique client identifier
        ws: WebSocket connection
        path: WebSocket path
    """
    try:
        # Add client to relay
        await relay.add(client_id, ws)
        
        # Send welcome message
        await ws.send(json.dumps({
            "type": "welcome",
            "protocol_version": PROTOCOL_VERSION,
            "client_id": client_id,
            "timestamp": relay.started_at
        }))
        
        # Handle incoming messages
        async for message in ws:
            try:
                data = message if isinstance(message, dict) else {}
                
                # Check rate limit
                relay.check_rate_limit(client_id)
                relay.record_message(client_id)
                
                # Relay the message to other clients
                if isinstance(message, str):
                    try:
                        data = {"data": message}
                    except:
                        data = {"raw": message}
                
                await relay.broadcast(client_id, data)
                
            except Exception as e:
                warn(f"Error handling message from {client_id}: {e}")
                log_security_event("message_error", {"client_id": client_id, "error": str(e)})
                
    except Exception as e:
        warn(f"Client {client_id} error: {e}")
    finally:
        await relay.remove(client_id)


async def main_server(host: str, port: int, token: str, max_clients: int):
    """
    Main server loop
    
    Args:
        host: Host to bind to
        port: Port to listen on
        token: Authentication token
        max_clients: Maximum number of concurrent clients
    """
    import websockets
    
    relay = BlindRelayServer(token)
    relay.max_clients = max_clients
    
    info(f"Starting P-521 Blind Relay Server")
    info(f"Protocol Version: {PROTOCOL_VERSION}")
    info(f"Token: {token[:8]}...{token[-8:]}")
    info(f"Host: {host}")
    info(f"Port: {port}")
    info(f"Max Clients: {max_clients}")
    info(f"Relay URL: ws://{host}:{port}/chat?token={token}")
    
    # Start stats loop
    stats_task = asyncio.create_task(relay.stats_loop())
    
    # WebSocket handler
    async def ws_handler(ws, path):
        # Extract token from path or query params
        query_token = None
        if path.startswith("/chat"):
            # Token in query params: /chat?token=XYZ
            if "token=" in path:
                query_token = path.split("token=")[1].split("&")[0]
        
        # Verify token
        if query_token != token:
            warn(f"Connection rejected: invalid token from {ws.remote_address}")
            await ws.close(code=1008, reason="Invalid token")
            log_security_event("invalid_token", {"remote_address": str(ws.remote_address)})
            return
        
        # Generate client ID
        client_id = f"{ws.remote_address[0]}_{secrets.token_hex(4)}"
        
        await handle_client(relay, client_id, ws, path)
    
    try:
        async with websockets.serve(ws_handler, host, port, max_size=32*1024*1024):
            info(f"Relay server listening on ws://{host}:{port}")
            info("Press Ctrl+C to stop the server")
            
            # Keep server running
            await asyncio.Future()
            
    except KeyboardInterrupt:
        info("\nShutting down relay server...")
    except Exception as e:
        warn(f"Server error: {e}")
        raise
    finally:
        stats_task.cancel()
        info(f"Relay server stopped. Total clients served: {len(relay.clients)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="P-521 Blind Relay Server - WebSocket relay for E2E encrypted messaging",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a secure token
  python run_relay.py --generate-token
  
  # Start server with custom token
  python run_relay.py --token my_secret_token --port 8080
  
  # Start server on all interfaces
  python run_relay.py --token my_secret_token --host 0.0.0.0 --port 8080
  
  # Start with default settings (generates random token)
  python run_relay.py
        """
    )
    
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="Authentication token for relay access (generates random if not provided)"
    )
    
    parser.add_argument(
        "--generate-token",
        action="store_true",
        help="Generate and display a secure token, then exit"
    )
    
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)"
    )
    
    parser.add_argument(
        "--max-clients",
        type=int,
        default=100,
        help="Maximum concurrent clients (default: 100)"
    )
    
    args = parser.parse_args()
    
    # Generate token if requested
    if args.generate_token:
        token = generate_token()
        print(f"Generated token: {token}")
        print(f"Relay URL: ws://127.0.0.1:8080/chat?token={token}")
        return
    
    # Use provided token or generate one
    token = args.token if args.token else generate_token()
    
    if not args.token:
        info(f"Generated token: {token}")
        info(f"Save this token to reuse it, or it will change each run")
    
    # Run server
    try:
        asyncio.run(main_server(args.host, args.port, token, args.max_clients))
    except KeyboardInterrupt:
        info("Server stopped by user")
    except Exception as e:
        console.print(f"[red][ERROR][/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
