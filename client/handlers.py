"""
Client handlers module - Message sending and receiving loops
"""

import asyncio
import json
import random
import time
from rich.table import Table
from rich import box
from websockets.exceptions import ConnectionClosed
from cryptography.exceptions import InvalidSignature, InvalidTag

from core.constants import console
from .room import ClientRoom

__all__ = [
    'client_sender_loop',
    'client_receiver_loop',
    'chat_help',
    'parse_dice',
    'room_art',
    'async_input',
    'async_confirm',
    'connection_health_monitor',
    'info',
    'good',
    'bad',
    'warn'
]


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


def chat_help() -> None:
    """Display chat help"""
    console.print()
    console.print(Panel(
        "Commands:\n"
        "/help - Show this help\n"
        "/quit - Leave the room\n"
        "/me <action> - Send an action\n"
        "/shout <text> - Send in uppercase\n"
        "/roll <expr> - Roll dice (e.g., d20, 4d6)\n"
        "/coin - Flip a coin\n"
        "/pulse - Send a pulse\n"
        "/art - Send ASCII art\n"
        "/file <path> - Send a file\n"
        "/participants or /who - Show participants\n"
        "/status - Show connection status\n"
        "/history - Show command history",
        title="Chat Commands",
        border_style="cyan",
    ))


def parse_dice(expr: str) -> tuple:
    """Parse dice expression like 'd20' or '4d6'"""
    if 'd' in expr:
        count, sides = expr.split('d')
        return int(count), int(sides)
    else:
        return 1, int(expr)


def room_art() -> str:
    """Generate ASCII art"""
    art = [
        "  ╔══════════════════════════════════════╗",
        "  ║  ██████╗ ██████╗ ██████╗ ███████╗    ║",
        "  ║  ██╔══██╗██╔══██╗██╔══██╗██╔════╝    ║",
        "  ║  ██║  ██║██████╔╝██████╔╝███████╗    ║",
        "  ║  ██║  ██║██╔══██╗██╔══██╗╚════██║    ║",
        "  ║  ██████╔╝██║  ██║██║  ██║███████║    ║",
        "  ║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ║",
        "  ║      E2E ENCRYPTED ROOM              ║",
        "  ╚══════════════════════════════════════╝",
    ]
    return "\n".join(art)


async def async_input(prompt: str) -> str:
    """Async input helper"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input, prompt)


async def async_confirm(prompt: str, default: bool = True) -> bool:
    """Async confirmation helper"""
    from rich.prompt import Confirm
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, Confirm.ask, prompt, default)


async def connection_health_monitor(room: ClientRoom) -> None:
    """Monitor connection health"""
    while room.connected:
        await asyncio.sleep(10)
        
        if time.time() - room.last_ping > 30:
            warn("No activity for 30 seconds. Connection may be stale.")
            room.connected = False
            break


async def client_sender_loop(room: ClientRoom) -> None:
    """Client message sending loop"""
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
            continue

        if text.startswith("/shout "):
            shout_text = text[7:].upper()
            await room.send_packet({
                "kind": "message",
                "body": shout_text,
            })
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
            except (ValueError, IndexError):
                warn("Usage: /roll d20 or /roll 4d6")
            continue

        if text == "/coin":
            result = random.choice(["heads", "tails"])
            await room.send_packet({
                "kind": "message",
                "body": f"🪙 flipped a coin: {result}",
            })
            continue

        if text == "/pulse":
            await room.send_packet({
                "kind": "message",
                "body": "💓 PULSE",
            })
            continue

        if text == "/art":
            await room.send_packet({
                "kind": "message",
                "body": room_art(),
            })
            continue

        if text.startswith("/file "):
            file_path_str = text[6:].strip()
            if not file_path_str:
                warn("Usage: /file PATH")
                continue

            from pathlib import Path
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
                    table.add_row(name, fp[:16] + "...")
                console.print(table)
            else:
                warn("No other participants detected yet.")
            continue

        if text == "/status":
            console.print()
            conn_status = "[green]Connected[/green]" if room.connected else "[red]Disconnected[/red]"
            last_activity = time.strftime('%H:%M:%S', time.localtime(room.last_ping))
            status_panel = (
                f"Connection: {conn_status}\n"
                f"Room ID: {room.room_id}\n"
                f"Participants: {len(room.participants)}\n"
                f"Last activity: {last_activity}"
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

        if text and not text.startswith("/"):
            room.command_history.append(text)
            if len(room.command_history) > 100:
                room.command_history.pop(0)


async def client_receiver_loop(room: ClientRoom) -> None:
    """Client message receiving loop"""
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
        room.cleanup()
