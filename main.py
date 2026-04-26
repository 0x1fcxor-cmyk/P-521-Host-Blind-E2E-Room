"""
P-521 Host-Blind E2E Room - Main Entry Point
Modular architecture with protocol, relay, client, storage, transport, and identity modules
"""

import sys
import os
import signal
import asyncio
import secrets
import subprocess
import json
import logging
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.text import Text

logger = logging.getLogger(__name__)

# Global shutdown flag
shutdown_requested = False


def setup_signal_handlers() -> None:
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        global shutdown_requested
        shutdown_requested = True
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        console.print("\n[yellow][WARN][/yellow] Shutdown signal received. Cleaning up...")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if os.name != "nt":  # Unix-like systems
        signal.signal(signal.SIGUSR1, signal_handler)
        signal.signal(signal.SIGUSR2, signal_handler)


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.constants import (
    APP_NAME, PROTOCOL_VERSION, APP_DIR, IDENTITY_FILE, PUBLIC_FILE,
    SETTINGS_FILE, TRUST_FILE, LOG_DIR, DOWNLOAD_DIR, CONFIG_FILE,
    DEFAULT_PORT_MIN, DEFAULT_PORT_MAX, MAX_WS_MESSAGE, console
)
from core.key_schedule import get_or_create_storage_salt
from identity.keys import Identity, load_identity, load_identity_from_file, generate_identity
from identity.trust import (
    get_settings, save_settings, load_trust, save_trust,
    trust_contact, trusted_name, default_settings, default_trust, normalize_fp
)
from protocol.envelopes import OverlayCrypto
from protocol.invites import build_e2e_invite, verify_e2e_invite
from relay.server import BlindRelayServer
from transport.cloudflare import (
    cloudflared_exists, start_cloudflare_tunnel, stop_cloudflare_tunnel,
    build_relay_link, strip_fragment, parse_invite, CloudflareTunnel, random_port
)
from storage.encrypted_db import init_db, store_message, get_thread_messages
from storage.vault import StorageVault
from client.room import ClientRoom
from client.handlers import client_sender_loop, client_receiver_loop


# Utility functions
def info(msg: str) -> None:
    console.print(f"[cyan][INFO][/cyan] {msg}")


def good(msg: str) -> None:
    console.print(f"[green][OK][/green] {msg}")


def bad(msg: str) -> None:
    console.print(f"[red][ERROR][/red] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][WARN][/yellow] {msg}")


def banner() -> None:
    console.print()
    console.print(Panel(
        Text(APP_NAME, style="bold cyan"),
        subtitle=f"Protocol: {PROTOCOL_VERSION}",
        border_style="cyan",
    ))
    console.print()


def ensure_dirs() -> None:
    """Ensure all required directories exist"""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    init_db()


def load_config() -> dict:
    """
    Load configuration from config.json with validation
    
    Returns:
        Validated configuration dictionary
    
    Raises:
        ValueError: If configuration is invalid
    """
    if CONFIG_FILE.exists():
        try:
            import json
            config = json.loads(CONFIG_FILE.read_text())
            
            # Validate configuration structure
            if not isinstance(config, dict):
                raise ValueError("Configuration must be a dictionary")
            
            # Validate default_port
            if "default_port" in config:
                port = config["default_port"]
                if port is not None:
                    if not isinstance(port, int):
                        raise ValueError("default_port must be an integer or null")
                    if port < 1024 or port > 65535:
                        raise ValueError("default_port must be between 1024 and 65535")
            
            # Validate relay_mode
            if "relay_mode" in config:
                mode = config["relay_mode"]
                if not isinstance(mode, str):
                    raise ValueError("relay_mode must be a string")
                if mode not in ["cloudflare", "direct"]:
                    raise ValueError("relay_mode must be 'cloudflare' or 'direct'")
            
            return config
        except json.JSONDecodeError as e:
            bad(f"Invalid JSON in config file: {e}")
            return {"default_port": None, "relay_mode": "cloudflare"}
        except ValueError as e:
            bad(f"Invalid configuration: {e}")
            return {"default_port": None, "relay_mode": "cloudflare"}
    
    return {"default_port": None, "relay_mode": "cloudflare"}


def save_config(config: dict) -> None:
    """
    Save configuration to config.json with validation
    
    Args:
        config: Configuration dictionary to save
    
    Raises:
        ValueError: If configuration is invalid
    """
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a dictionary")
    
    # Validate before saving
    if "default_port" in config:
        port = config["default_port"]
        if port is not None:
            if not isinstance(port, int):
                raise ValueError("default_port must be an integer or null")
            if port < 1024 or port > 65535:
                raise ValueError("default_port must be between 1024 and 65535")
    
    if "relay_mode" in config:
        mode = config["relay_mode"]
        if not isinstance(mode, str):
            raise ValueError("relay_mode must be a string")
        if mode not in ["cloudflare", "direct"]:
            raise ValueError("relay_mode must be 'cloudflare' or 'direct'")
    
    import json
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def generate_room_key() -> str:
    """Generate a random room key"""
    return secrets.token_urlsafe(32)


def decode_room_key(room_key_text: str) -> bytes:
    """Decode room key from text format"""
    import base64
    return base64.urlsafe_b64decode(room_key_text.encode("utf-8"))


def room_id_from_key_text(room_key_text: str) -> str:
    """Generate room ID from room key text"""
    import hashlib
    return hashlib.sha256(room_key_text.encode()).hexdigest()[:24].upper()


def human_bytes(n: int) -> str:
    """Convert bytes to human-readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def vpn_warning_gate(action: str) -> bool:
    """Show VPN warning and get confirmation"""
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

    return Confirm.ask("I understand the risks and want to continue", default=False)


def import_room_key(identity: Identity) -> None:
    """Import and validate a room key"""
    banner()
    
    room_key_text = Prompt.ask("Enter room key (base64)")
    
    # Input validation
    if not room_key_text or not room_key_text.strip():
        bad("Room key cannot be empty")
        input("\nPress Enter...")
        return
    
    room_key_text = room_key_text.strip()
    
    # Validate base64 format (basic check)
    import base64
    try:
        # Check if it's valid base64
        base64.urlsafe_b64decode(room_key_text + "=" * (-len(room_key_text) % 4))
    except Exception:
        bad("Invalid base64 format for room key")
        input("\nPress Enter...")
        return
    
    try:
        room_key = decode_room_key(room_key_text)
        room_id = room_id_from_key_text(room_key_text)
        
        console.print(Panel(
            f"Room ID:\n{room_id}\n\n"
            f"Room key decoded successfully.\n\n"
            "[yellow]Security Note:[/yellow]\n"
            "Store this room key securely. Anyone with this key can decrypt room messages.",
            title="Room Key Imported",
            border_style="green",
        ))
        
        # Optionally save to a file
        if Confirm.ask("Save room key to file?", default=False):
            key_file = Prompt.ask("Key file path", default="room_key.txt")
            key_file = key_file.strip()
            
            # Validate file path
            if not key_file:
                bad("File path cannot be empty")
            else:
                # Security: prevent path traversal
                if ".." in key_file or key_file.startswith("/") or (len(key_file) > 1 and key_file[1] == ":"):
                    bad("Invalid file path: path traversal not allowed")
                else:
                    try:
                        key_path = Path(key_file)
                        key_path.parent.mkdir(parents=True, exist_ok=True)
                        key_path.write_text(room_key_text)
                        good(f"Room key saved to {key_file}")
                    except Exception as e:
                        bad(f"Failed to save room key: {e}")
        
    except Exception as e:
        bad(f"Failed to decode room key: {e}")
    
    input("\nPress Enter...")


async def join_e2e_room(identity: Identity) -> None:
    """Join a host-blind E2E room"""
    if not vpn_warning_gate("join a host-blind E2E room"):
        warn("Join cancelled. Connect to VPN first.")
        input("\nPress Enter...")
        return

    banner()

    raw = Prompt.ask("Paste full E2E invite link")
    
    # Input validation
    if not raw or not raw.strip():
        bad("Invite link cannot be empty")
        input("\nPress Enter...")
        return
    
    raw = raw.strip()
    
    try:
        ws_url, token, room_key_text = parse_invite(raw)
    except ValueError as e:
        bad(f"Invalid invite link format: {e}")
        input("\nPress Enter...")
        return
    except Exception as e:
        bad(f"Failed to parse invite link: {e}")
        input("\nPress Enter...")
        return
    
    if not room_key_text:
        bad("No room key found in invite link.")
        input("\nPress Enter...")
        return
    
    if not ws_url:
        bad("No WebSocket URL found in invite link.")
        input("\nPress Enter...")
        return
    
    try:
        room_key = decode_room_key(room_key_text)
        overlay = OverlayCrypto(identity, room_key)
    except Exception as e:
        bad(f"Failed to initialize overlay crypto: {e}")
        input("\nPress Enter...")
        return

    # Start web UI server with auto-login
    web_ui_process = None
    web_ui_port = None
    password = None
    
    try:
        import getpass
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

            import websockets
            from websockets.exceptions import ConnectionClosed

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
        finally:
            if web_ui_process:
                info("Stopping web UI server...")
                web_ui_process.terminate()
                try:
                    web_ui_process.wait(timeout=5)
                except:
                    web_ui_process.kill()


async def host_blind_relay() -> None:
    """Host a blind relay server"""
    if not vpn_warning_gate("host a blind relay"):
        warn("Hosting cancelled. Connect to VPN first.")
        input("\nPress Enter...")
        return

    banner()

    # Get identity for web UI auto-login
    identity = None
    password = None
    if IDENTITY_FILE.exists():
        import getpass
        password = getpass.getpass("Enter password for identity (leave empty to skip web UI auto-login): ")
        if password:
            try:
                identity = load_identity_from_file(password)
            except Exception as e:
                warn(f"Failed to load identity: {e}")
                password = None

    config = load_config()
    default_port = config.get("default_port")
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

    # Start Cloudflare tunnel
    relay_mode = config.get("relay_mode", "cloudflare")
    
    if relay_mode == "cloudflare":
        tunnel = await start_cloudflare_tunnel(local_port)
        relay_link = build_relay_link(tunnel.url, token)
    else:
        # Placeholder for other modes
        relay_link = f"ws://127.0.0.1:{local_port}/chat?token={token}"

    console.print(Panel(
        f"Relay mode: {relay_mode.upper()}\n\n"
        f"Relay link:\n{relay_link}\n\n"
        f"Share this link with others to join your relay.\n\n"
        f"[yellow]Security Note:[/yellow]\n"
        f"• Cloudflare mode: Cloudflare can see connection metadata\n"
        f"• Tor mode: Use .onion address for maximum privacy\n"
        f"• WireGuard mode: Requires VPN configuration\n"
        f"• LAN mode: Only accessible on local network",
        title="Blind Relay Running",
        border_style="green",
    ))

    # Start WebSocket server
    import websockets
    from urllib.parse import urlparse, parse_qs

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

            await ws.send_json({
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

        except Exception as e:
            warn(f"Client error: {e}")
        finally:
            await relay.remove(client_id)

    async with websockets.serve(handler, "127.0.0.1", local_port):
        console.print(f"[green]Relay server listening on 127.0.0.1:{local_port}[/green]")
        
        # Start stats loop
        stats_task = asyncio.create_task(relay.stats_loop())
        
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            info("Shutting down relay...")
            stats_task.cancel()
        finally:
            if web_ui_process:
                info("Stopping web UI server...")
                web_ui_process.terminate()
                try:
                    web_ui_process.wait(timeout=5)
                except:
                    web_ui_process.kill()
            
            if relay_mode == "cloudflare" and tunnel:
                stop_cloudflare_tunnel(tunnel)


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
    return process


def make_e2e_invite_tool() -> None:
    """Tool to create E2E invite links"""
    banner()

    # Load identity for signing
    identity = None
    if IDENTITY_FILE.exists():
        import getpass
        password = getpass.getpass("Enter password for identity (leave empty for unsigned invite): ")
        if password:
            try:
                identity = load_identity_from_file(password)
            except Exception as e:
                warn(f"Failed to load identity: {e}")
                console.print("[yellow]Creating unsigned invite (no signature, no expiration)[/yellow]")
    
    relay_link = Prompt.ask("Paste relay link without room key")
    
    # Input validation
    if not relay_link or not relay_link.strip():
        bad("Relay link cannot be empty")
        input("\nPress Enter...")
        return
    
    relay_link = relay_link.strip()
    
    room_key = generate_room_key()
    
    # Ask for invite parameters if identity is available
    if identity:
        expires_in = IntPrompt.ask("Invite expires in hours", default=24)
        max_uses = IntPrompt.ask("Maximum uses", default=1)
        role = Prompt.ask("Role", default="member", choices=["member", "admin"])
        
        # Validate parameters
        if expires_in <= 0:
            bad("Expiration must be positive")
            input("\nPress Enter...")
            return
        
        if max_uses <= 0:
            bad("Maximum uses must be positive")
            input("\nPress Enter...")
            return
        
        try:
            invite = build_e2e_invite(relay_link, room_key, identity, expires_in, max_uses, role)
        except ValueError as e:
            bad(f"Invalid parameters: {e}")
            input("\nPress Enter...")
            return
        except Exception as e:
            bad(f"Failed to build invite: {e}")
            input("\nPress Enter...")
            return
    else:
        try:
            invite = build_e2e_invite(relay_link, room_key)  # Unsigned
        except Exception as e:
            bad(f"Failed to build invite: {e}")
            input("\nPress Enter...")
            return
    
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


def show_fingerprint(identity: Identity) -> None:
    """Display the user's fingerprint"""
    banner()
    console.print(Panel(
        identity.fingerprint,
        title="Your P-521 Identity Fingerprint",
        border_style="green",
    ))
    input("\nPress Enter...")


def export_public_identity(identity: Identity) -> None:
    """Export public identity to file"""
    banner()
    
    output_file = Prompt.ask("Output file", default="identity_public.pem")
    
    # Input validation and security check
    if not output_file or not output_file.strip():
        bad("Output file cannot be empty")
        input("\nPress Enter...")
        return
    
    output_file = output_file.strip()
    
    # Security: prevent path traversal
    if ".." in output_file or output_file.startswith("/") or (len(output_file) > 1 and output_file[1] == ":"):
        bad("Invalid file path: path traversal not allowed")
        input("\nPress Enter...")
        return
    
    # Security: only allow .pem extension
    if not output_file.lower().endswith(".pem"):
        bad("Output file must have .pem extension")
        input("\nPress Enter...")
        return
    
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(identity.public_pem)
        good(f"Public identity exported to {output_file}")
    except Exception as e:
        bad(f"Failed to export identity: {e}")
    
    input("\nPress Enter...")


def trusted_contacts_menu(identity: Identity) -> None:
    """Trusted contacts management menu"""
    while True:
        banner()

        trust = load_trust(identity)
        contacts = trust.get("contacts_by_fingerprint", {})

        table = Table(box=None, show_header=False)
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Action")

        table.add_row("1", "Add trusted contact")
        table.add_row("2", "List trusted contacts")
        table.add_row("3", "Remove trusted contact")
        table.add_row("4", "Import public key")
        table.add_row("0", "Back")

        console.print(table)

        choice = Prompt.ask("Choose", default="0")

        if choice == "1":
            fp = Prompt.ask("Enter fingerprint (with or without colons)")
            name = Prompt.ask("Enter display name")
            
            # Input validation
            if not fp or not fp.strip():
                bad("Fingerprint cannot be empty")
                input("\nPress Enter...")
                continue
            
            if not name or not name.strip():
                bad("Display name cannot be empty")
                input("\nPress Enter...")
                continue
            
            fp = fp.strip()
            name = name.strip()
            
            try:
                trust_contact(identity, fp, name)
                good(f"Added {name} to trusted contacts.")
            except ValueError as e:
                bad(f"Invalid input: {e}")
            except Exception as e:
                bad(f"Failed to add contact: {e}")

        elif choice == "2":
            if contacts:
                console.print()
                table = Table(title="Trusted Contacts", box=None)
                table.add_column("Name", style="cyan")
                table.add_column("Fingerprint", style="dim")
                table.add_column("Trusted At", style="dim")
                
                for nfp, contact in contacts.items():
                    table.add_row(
                        contact["name"],
                        contact["fingerprint"],
                        time.strftime('%Y-%m-%d %H:%M', time.localtime(contact["trusted_at"]))
                    )
                console.print(table)
            else:
                warn("No trusted contacts yet.")
            input("\nPress Enter...")

        elif choice == "3":
            if not contacts:
                warn("No trusted contacts to remove.")
                input("\nPress Enter...")
                continue
            
            fp = Prompt.ask("Enter fingerprint to remove")
            
            # Input validation
            if not fp or not fp.strip():
                bad("Fingerprint cannot be empty")
                input("\nPress Enter...")
                continue
            
            fp = fp.strip()
            
            try:
                nfp = normalize_fp(fp)
            except ValueError as e:
                bad(f"Invalid fingerprint format: {e}")
                input("\nPress Enter...")
                continue
            
            if nfp in contacts:
                del trust["contacts_by_fingerprint"][nfp]
                # Remove from nickname index
                name = contacts[nfp]["name"]
                if name.lower() in trust.get("nickname_index", {}):
                    del trust["nickname_index"][name.lower()]
                
                try:
                    save_trust(identity, trust)
                    good(f"Removed contact with fingerprint {fp}.")
                except Exception as e:
                    bad(f"Failed to save trust store: {e}")
            else:
                warn("Contact not found.")

        elif choice == "4":
            import getpass
            file_path = Prompt.ask("Enter path to public key file")
            
            # Input validation
            if not file_path or not file_path.strip():
                bad("File path cannot be empty")
                input("\nPress Enter...")
                continue
            
            file_path = file_path.strip()
            
            # Security: prevent path traversal
            if ".." in file_path or file_path.startswith("/") or (len(file_path) > 1 and file_path[1] == ":"):
                bad("Invalid file path: path traversal not allowed")
                input("\nPress Enter...")
                continue
            
            # Security: only allow .pem extension
            if not file_path.lower().endswith(".pem"):
                bad("File must have .pem extension")
                input("\nPress Enter...")
                continue
            
            path = Path(file_path)
            
            if not path.exists():
                bad("File not found.")
                input("\nPress Enter...")
                continue
            
            try:
                from cryptography.hazmat.primitives import serialization
                pem_data = path.read_bytes()
                public_key = serialization.load_pem_public_key(pem_data)
                
                public_der = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                fp = hashlib.sha256(public_der).hexdigest().upper()
                
                name = Prompt.ask("Enter display name for this key")
                
                # Validate name
                if not name or not name.strip():
                    bad("Display name cannot be empty")
                    input("\nPress Enter...")
                    continue
                
                name = name.strip()
                
                trust_contact(identity, fp, name)
                good(f"Imported and trusted {name}.")
            except ValueError as e:
                bad(f"Invalid key format: {e}")
            except Exception as e:
                bad(f"Failed to import key: {e}")

        elif choice == "0":
            break


def settings_menu(identity: Identity) -> None:
    """Settings menu"""
    while True:
        banner()

        settings = get_settings(identity)

        table = Table(box=None, show_header=False)
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Action")

        table.add_row("1", "Change display name")
        table.add_row("2", "Set max file size")
        table.add_row("3", "Set default port")
        table.add_row("4", "Set relay mode")
        table.add_row("0", "Back")

        console.print(table)

        choice = Prompt.ask("Choose", default="0")

        if choice == "1":
            display_name = Prompt.ask("Display name", default=settings.get("display_name", identity.display_name))
            settings["display_name"] = display_name
            save_settings(identity, settings)
            good("Display name updated.")

        elif choice == "2":
            max_size = IntPrompt.ask("Max file size (MB)", default=settings.get("max_file_size", 100) // (1024 * 1024))
            settings["max_file_size"] = max_size * 1024 * 1024
            save_settings(identity, settings)
            good(f"Max file size set to {max_size} MB.")

        elif choice == "3":
            config = load_config()
            port = IntPrompt.ask("Default port", default=config.get("default_port") or random_port())
            config["default_port"] = port
            save_config(config)
            good(f"Default port set to {port}.")

        elif choice == "4":
            config = load_config()
            mode = Prompt.ask("Relay mode", default=config.get("relay_mode", "cloudflare"), 
                            choices=["cloudflare", "tor", "wireguard", "lan"])
            config["relay_mode"] = mode
            save_config(config)
            good(f"Relay mode set to {mode}.")

        elif choice == "0":
            break


def reset_identity() -> None:
    """Reset identity and storage"""
    banner()

    console.print(Panel(
        "This will delete:\n\n"
        "• Your P-521 identity keys\n"
        "• All encrypted settings\n"
        "• Trust store\n"
        "• Message database\n\n"
        "This action cannot be undone!",
        title="⚠️  DANGER: RESET IDENTITY",
        border_style="red",
    ))

    if not Confirm.ask("Are you sure you want to reset everything?", default=False):
        warn("Reset cancelled.")
        return

    if not Confirm.ask("Are you REALLY sure? This will delete your identity!", default=False):
        warn("Reset cancelled.")
        return

    # Delete all files
    for file in [IDENTITY_FILE, PUBLIC_FILE, SETTINGS_FILE, TRUST_FILE, CONFIG_FILE]:
        if file.exists():
            file.unlink()

    # Delete database
    db_file = APP_DIR / "messages.db"
    if db_file.exists():
        db_file.unlink()

    good("Identity and storage reset.")
    input("\nPress Enter...")


def main_menu(identity: Identity) -> None:
    """Main CLI menu"""
    while True:
        banner()

        settings = get_settings(identity)

        table = Table(box=None, show_header=False)
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
            f"Max file size: {human_bytes(int(settings.get('max_file_size', 100 * 1024 * 1024)))}\n"
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
            import_room_key(identity)

        elif choice == "5":
            show_fingerprint(identity)

        elif choice == "6":
            export_public_identity(identity)

        elif choice == "7":
            trusted_contacts_menu(identity)

        elif choice == "8":
            settings_menu(identity)

        elif choice == "9":
            console.print("[yellow]Security model documentation: See THREAT_MODEL.md[/yellow]")
            input("\nPress Enter...")

        elif choice == "10":
            reset_identity()
            return  # Exit after reset

        elif choice == "0":
            console.print("Goodbye!")
            sys.exit(0)


def main() -> None:
    """Main entry point"""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s:%(name)s:%(message)s'
    )
    
    ensure_dirs()
    setup_signal_handlers()
    
    try:
        identity = load_identity()
        main_menu(identity)
    except KeyboardInterrupt:
        console.print("\nGoodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
