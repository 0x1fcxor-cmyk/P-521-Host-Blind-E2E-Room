"""
P-521 Host-Blind E2E Room - Web UI Server
Flask-based web interface for the secure communication application
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import webbrowser
import websockets
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs

from flask import Flask, render_template, request, jsonify, session, send_from_directory
from flask_socketio import SocketIO, emit

# Import shared crypto logic from main script
import sys
import importlib.util
spec = importlib.util.spec_from_file_location("securecoms", Path(__file__).parent / "0x1FC_p-521_E2E_SecureComs.py")
securecoms = importlib.util.module_from_spec(spec)
sys.modules['securecoms'] = securecoms
spec.loader.exec_module(securecoms)

APP_DIR = securecoms.APP_DIR
IDENTITY_FILE = securecoms.IDENTITY_FILE
PUBLIC_FILE = securecoms.PUBLIC_FILE
STORAGE_SALT_FILE = securecoms.STORAGE_SALT_FILE
SETTINGS_FILE = securecoms.SETTINGS_FILE
TRUST_FILE = securecoms.TRUST_FILE
LOG_DIR = securecoms.LOG_DIR
DOWNLOAD_DIR = securecoms.DOWNLOAD_DIR
APP_NAME = securecoms.APP_NAME
PROTOCOL_VERSION = securecoms.PROTOCOL_VERSION
STORAGE_AAD = securecoms.STORAGE_AAD
OVERLAY_AAD = securecoms.OVERLAY_AAD
DEFAULT_MAX_FILE_SIZE = securecoms.DEFAULT_MAX_FILE_SIZE
FILE_CHUNK_SIZE = securecoms.FILE_CHUNK_SIZE
ensure_dirs = securecoms.ensure_dirs
human_bytes = securecoms.human_bytes
safe_name = securecoms.safe_name
unique_path = securecoms.unique_path
b64e = securecoms.b64e
b64d = securecoms.b64d
now = securecoms.now
short_fp = securecoms.short_fp

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
active_rooms: Dict[str, 'WebRoom'] = {}
active_identities: Dict[str, 'Identity'] = {}

ensure_dirs()


# Auto-login credentials from environment
AUTO_PASSWORD = os.environ.get('P521_AUTO_PASSWORD')
AUTO_FINGERPRINT = os.environ.get('P521_AUTO_FINGERPRINT')
AUTO_DISPLAY_NAME = os.environ.get('P521_AUTO_DISPLAY_NAME')
AUTO_INVITE_LINK = os.environ.get('P521_AUTO_INVITE_LINK')
AUTO_LOGIN_ENABLED = '--auto-login' in sys.argv or AUTO_PASSWORD is not None


# Use Identity class from main application
Identity = securecoms.Identity


@dataclass
class WebRoom:
    ws_url: str
    token: str
    room_key: str
    room_id: str
    identity: Identity
    participants: Dict[str, str] = field(default_factory=dict)
    messages: list = field(default_factory=list)
    connected: bool = False
    last_activity: float = field(default_factory=time.time)
    websocket: Optional[object] = None
    overlay: Optional[object] = None
    receive_task: Optional[object] = None


def generate_identity(password: str, display_name: str = "User") -> Identity:
    """Generate a new P-521 identity using the main application's function"""
    # Use the main application's generate_identity function
    return securecoms.generate_identity(display_name, password)


def save_identity(identity: Identity, password: str) -> None:
    """Save identity to disk using the main application's function"""
    # Use the main application's private_to_encrypted_pem and save functions
    from identity.keys import private_to_encrypted_pem
    
    # Ensure password is bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Encrypt private key with password
    encrypted_pem = private_to_encrypted_pem(identity.private_key, password)
    
    # Save files
    IDENTITY_FILE.write_bytes(encrypted_pem)
    PUBLIC_FILE.write_bytes(identity.public_pem)


def load_identity(password: str) -> Optional[Identity]:
    """Load identity from disk using the main application's function"""
    try:
        # Use the main application's load_identity_from_file function
        return securecoms.load_identity_from_file(password)
    except ValueError as e:
        print(f"[DEBUG] load_identity ValueError: {e}")
        return None
    except Exception as e:
        print(f"[DEBUG] load_identity exception: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return None


# Routes
@app.route('/')
def index():
    """Serve the main UI"""
    return render_template('index.html')


@app.route('/api/auto-login', methods=['GET'])
def auto_login():
    """Handle auto-login from CLI"""
    if not AUTO_LOGIN_ENABLED or not AUTO_PASSWORD:
        return jsonify({'success': False, 'error': 'Auto-login not enabled'})
    
    try:
        identity = load_identity(AUTO_PASSWORD)
        if not identity:
            return jsonify({'success': False, 'error': 'Invalid credentials'})
        
        session['identity_loaded'] = True
        session['password'] = AUTO_PASSWORD
        session['fingerprint'] = identity.fingerprint
        session['display_name'] = identity.display_name
        
        response_data = {
            'success': True,
            'fingerprint': identity.fingerprint,
            'display_name': identity.display_name,
            'auto_logged_in': True
        }
        
        if AUTO_INVITE_LINK:
            response_data['invite_link'] = AUTO_INVITE_LINK
        
        return jsonify(response_data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/identity/status', methods=['GET'])
def identity_status():
    """Check if identity exists"""
    exists = IDENTITY_FILE.exists()
    return jsonify({'exists': exists})


@app.route('/api/identity/create', methods=['POST'])
def create_identity():
    """Create a new identity"""
    data = request.json
    password = data.get('password', '')
    display_name = data.get('display_name', 'User')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    if IDENTITY_FILE.exists():
        return jsonify({'error': 'Identity already exists'}), 400
    
    try:
        identity = generate_identity(password, display_name)
        save_identity(identity, password)
        return jsonify({'success': True, 'fingerprint': identity.fingerprint})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/identity/load', methods=['POST'])
def load_identity_endpoint():
    """Load existing identity"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    print(f"[DEBUG] Attempting to load identity with password length: {len(password)}")
    print(f"[DEBUG] Identity file exists: {IDENTITY_FILE.exists()}")
    
    identity = load_identity(password)
    
    if not identity:
        print(f"[DEBUG] Failed to load identity")
        return jsonify({'error': 'Invalid password or identity not found'}), 401
    
    print(f"[DEBUG] Successfully loaded identity: {identity.fingerprint[:16]}...")
    
    session['identity_loaded'] = True
    session['password'] = password  # Store for crypto operations
    session['fingerprint'] = identity.fingerprint
    session['display_name'] = identity.display_name
    
    return jsonify({
        'success': True,
        'fingerprint': identity.fingerprint,
        'display_name': identity.display_name
    })


@app.route('/api/room/create', methods=['POST'])
def create_room():
    """Create a new room and generate invite link"""
    if not session.get('identity_loaded'):
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.json
        relay_url = data.get('relay_url', '')
        
        if not relay_url:
            return jsonify({'error': 'Relay URL required'}), 400
        
        # Parse relay URL to get token
        parsed = urlparse(relay_url)
        token = parse_qs(parsed.query).get('token', [''])[0]
        
        if not token:
            return jsonify({'error': 'Relay URL must contain token'}), 400
        
        # Generate room key
        room_key = securecoms.generate_room_key()
        room_key_bytes = securecoms.decode_room_key(room_key)
        room_id = hashlib.sha256(room_key_bytes).hexdigest()[:16]
        
        # Load identity from session
        password = session.get('password')
        identity = load_identity(password)
        if not identity:
            return jsonify({'error': 'Failed to load identity'}), 500
        
        # Create overlay crypto
        overlay = securecoms.OverlayCrypto(identity, room_key_bytes)
        
        # Construct WebSocket URL
        scheme = "wss" if parsed.scheme in ("https", "wss") else "ws"
        ws_url = f"{scheme}://{parsed.netloc}{parsed.path}"
        
        room_id_str = secrets.token_hex(8)
        room = WebRoom(
            ws_url=ws_url,
            token=token,
            room_key=room_key,
            room_id=room_id,
            identity=identity,
            overlay=overlay
        )
        
        active_rooms[room_id_str] = room
        
        # Start WebSocket connection in background thread
        import threading
        thread = threading.Thread(target=run_websocket_connection, args=(room_id_str,))
        thread.daemon = True
        thread.start()
        
        # Generate invite link with room key
        invite_link = f"{relay_url}#rk={room_key}"
        
        return jsonify({
            'success': True,
            'room_id': room_id_str,
            'room_id_display': room_id,
            'room_key': room_key,
            'invite_link': invite_link,
            'ws_url': ws_url
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/room/join', methods=['POST'])
def join_room():
    """Join a room with invite link"""
    if not session.get('identity_loaded'):
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.json
    invite_link = data.get('invite_link', '')
    
    if not invite_link:
        return jsonify({'error': 'Invite link required'}), 400
    
    # Parse invite link
    try:
        ws_url, token, room_key = securecoms.parse_invite(invite_link)
        
        if not token or not room_key:
            return jsonify({'error': 'Invalid invite link'}), 400
        
        # Generate room ID from key
        room_key_bytes = securecoms.decode_room_key(room_key)
        room_id = hashlib.sha256(room_key_bytes).hexdigest()[:16]
        
        # Load identity from session
        password = session.get('password')
        identity = load_identity(password)
        if not identity:
            return jsonify({'error': 'Failed to load identity'}), 500
        
        # Create overlay crypto
        overlay = securecoms.OverlayCrypto(identity, room_key_bytes)
        
        room_id_str = secrets.token_hex(8)
        room = WebRoom(
            ws_url=ws_url,
            token=token,
            room_key=room_key,
            room_id=room_id,
            identity=identity,
            overlay=overlay
        )
        
        active_rooms[room_id_str] = room
        
        # Start WebSocket connection in background thread
        import threading
        thread = threading.Thread(target=run_websocket_connection, args=(room_id_str,))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'room_id': room_id_str,
            'ws_url': ws_url,
            'room_id_display': room_id
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


def run_websocket_connection(room_id_str: str):
    """Run WebSocket connection in a separate thread with its own event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(connect_room_websocket(room_id_str))
    finally:
        loop.close()


async def connect_room_websocket(room_id_str: str):
    """Connect to room WebSocket and handle messages"""
    if room_id_str not in active_rooms:
        return
    
    room = active_rooms[room_id_str]
    
    try:
        async with websockets.connect(
            room.ws_url,
            max_size=10 * 1024 * 1024,
            ping_interval=20,
            ping_timeout=20,
            close_timeout=10,
        ) as ws:
            room.websocket = ws
            room.connected = True
            
            # Send join announcement
            packet = {
                "kind": "system_join",
                "body": f"{room.identity.display_name} joined the E2E overlay.",
            }
            envelope = room.overlay.encrypt_packet(packet)
            await ws.send(json.dumps(envelope))
            
            # Receive loop
            async for message in ws:
                try:
                    envelope = json.loads(message)
                    decrypted = room.overlay.decrypt_envelope(envelope)
                    
                    if decrypted:
                        room.messages.append({
                            'type': 'received',
                            'content': decrypted.get('body', ''),
                            'sender': decrypted.get('sender_name', 'Unknown'),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Emit to Flask-SocketIO
                        socketio.emit('message', {
                            'room_id': room_id_str,
                            'type': 'received',
                            'content': decrypted.get('body', ''),
                            'sender': decrypted.get('sender_name', 'Unknown'),
                            'timestamp': datetime.now().isoformat()
                        })
                except Exception as e:
                    print(f"Error processing message: {e}")
                    
    except Exception as e:
        print(f"WebSocket connection error: {e}")
        room.connected = False


@app.route('/api/room/<room_id>/message', methods=['POST'])
def send_message(room_id):
    """Send a message to the room"""
    if room_id not in active_rooms:
        return jsonify({'error': 'Room not found'}), 404
    
    data = request.json
    message = data.get('message', '')
    
    if not message:
        return jsonify({'error': 'Message required'}), 400
    
    room = active_rooms[room_id]
    
    # Add to local messages
    room.messages.append({
        'type': 'sent',
        'content': message,
        'timestamp': datetime.now().isoformat(),
        'sender': session.get('display_name', 'You')
    })
    
    # Send via WebSocket if connected
    if room.websocket and room.connected:
        try:
            packet = {
                "kind": "message",
                "body": message,
            }
            envelope = room.overlay.encrypt_packet(packet)
            
            # Send in async context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(room.websocket.send(json.dumps(envelope)))
            finally:
                loop.close()
        except Exception as e:
            print(f"Error sending message: {e}")
    
    # Emit to Flask-SocketIO
    socketio.emit('message', {
        'room_id': room_id,
        'type': 'sent',
        'content': message,
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({'success': True})


@app.route('/api/room/<room_id>/messages', methods=['GET'])
def get_messages(room_id):
    """Get message history for a room"""
    if room_id not in active_rooms:
        return jsonify({'error': 'Room not found'}), 404
    
    room = active_rooms[room_id]
    return jsonify({'messages': room.messages})


@app.route('/api/room/<room_id>/leave', methods=['POST'])
def leave_room(room_id):
    """Leave a room"""
    if room_id in active_rooms:
        del active_rooms[room_id]
    
    return jsonify({'success': True})


@app.route('/api/settings', methods=['GET', 'POST'])
def settings():
    """Get or update settings"""
    if request.method == 'GET':
        # Return current settings
        return jsonify({
            'display_name': session.get('display_name', 'User'),
            'max_file_size': DEFAULT_MAX_FILE_SIZE
        })
    else:
        # Update settings
        data = request.json
        display_name = data.get('display_name')
        if display_name:
            session['display_name'] = display_name
        return jsonify({'success': True})


@app.route('/api/identity/export', methods=['GET'])
def export_identity():
    """Export identity as JSON"""
    if not session.get('identity_loaded'):
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        # Load identity from session storage
        password = session.get('password')
        if not password:
            return jsonify({'error': 'Password not in session'}), 400
        
        identity = load_identity(password)
        if not identity:
            return jsonify({'error': 'Failed to load identity'}), 500
        
        export_data = {
            'app': APP_NAME,
            'protocol': PROTOCOL_VERSION,
            'display_name': identity.display_name,
            'fingerprint': identity.fingerprint,
            'public_pem': identity.public_pem.decode('utf-8'),
            'exported_at': datetime.now().isoformat()
        }
        
        return jsonify({'success': True, 'data': export_data})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/identity/import', methods=['POST'])
def import_identity():
    """Import identity from JSON"""
    data = request.json
    identity_data = data.get('data')
    
    if not identity_data:
        return jsonify({'error': 'No identity data provided'}), 400
    
    try:
        # Validate identity data
        if identity_data.get('app') != APP_NAME:
            return jsonify({'error': 'Invalid identity format'}), 400
        
        if identity_data.get('protocol') != PROTOCOL_VERSION:
            return jsonify({'error': 'Protocol version mismatch'}), 400
        
        # Store public key
        PUBLIC_FILE.write_bytes(identity_data['public_pem'].encode('utf-8'))
        
        return jsonify({'success': True, 'fingerprint': identity_data['fingerprint']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/trust/contacts', methods=['GET', 'POST'])
def trust_contacts():
    """Get or update trusted contacts"""
    if not session.get('identity_loaded'):
        return jsonify({'error': 'Not logged in'}), 401
    
    if request.method == 'GET':
        # Return trusted contacts
        try:
            password = session.get('password')
            if not password:
                return jsonify({'error': 'Password not in session'}), 400
            
            identity = load_identity(password)
            if not identity:
                return jsonify({'error': 'Failed to load identity'}), 500
            
            # Load trust file
            if TRUST_FILE.exists():
                trust_data = TRUST_FILE.read_bytes()
                if len(trust_data) > 12:
                    nonce = trust_data[:12]
                    encrypted = trust_data[12:]
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(identity.storage_key)
                    decrypted = aesgcm.decrypt(nonce, encrypted, STORAGE_AAD)
                    trust = json.loads(decrypted)
                    contacts = trust.get('contacts_by_fingerprint', {})
                    return jsonify({'success': True, 'contacts': list(contacts.values())})
            
            return jsonify({'success': True, 'contacts': []})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    else:
        # Add trusted contact
        contact_data = request.json
        fingerprint = contact_data.get('fingerprint')
        name = contact_data.get('name')
        
        if not fingerprint or not name:
            return jsonify({'error': 'Fingerprint and name required'}), 400
        
        try:
            password = session.get('password')
            if not password:
                return jsonify({'error': 'Password not in session'}), 400
            
            identity = load_identity(password)
            if not identity:
                return jsonify({'error': 'Failed to load identity'}), 500
            
            # Load existing trust
            trust = {}
            if TRUST_FILE.exists():
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                trust_data = TRUST_FILE.read_bytes()
                if len(trust_data) > 12:
                    nonce = trust_data[:12]
                    encrypted = trust_data[12:]
                    aesgcm = AESGCM(identity.storage_key)
                    decrypted = aesgcm.decrypt(nonce, encrypted, STORAGE_AAD)
                    trust = json.loads(decrypted)
            
            # Add contact
            if 'contacts_by_fingerprint' not in trust:
                trust['contacts_by_fingerprint'] = {}
            
            trust['contacts_by_fingerprint'][fingerprint] = {
                'name': name,
                'fingerprint': fingerprint,
                'trusted_at': datetime.now().isoformat()
            }
            
            # Save trust
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(identity.storage_key)
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, json.dumps(trust).encode(), STORAGE_AAD)
            TRUST_FILE.write_bytes(nonce + encrypted)
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'status': 'connected'})


@socketio.on('join_room')
def handle_join_room(data):
    """Handle joining a room via WebSocket"""
    room_id = data.get('room_id')
    if room_id:
        from flask_socketio import join_room
        join_room(room_id)
        emit('joined', {'room_id': room_id})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P-521 Web UI Server')
    parser.add_argument('--port', type=int, default=None, help='Port to run the server on (default: random or 5000)')
    parser.add_argument('--auto-login', action='store_true', help='Enable auto-login from environment variables')
    parser.add_argument('--no-browser', action='store_true', help='Do not auto-open browser')
    args = parser.parse_args()

    # Use port from environment variable if set, otherwise use CLI arg, otherwise random, otherwise 5000
    port = args.port
    if port is None:
        env_port = os.environ.get('P521_WEB_UI_PORT')
        if env_port:
            port = int(env_port)
        else:
            # Try random port if none specified
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', 0))
            port = s.getsockname()[1]
            s.close()

    print("Starting P-521 Web UI Server...")
    print(f"Identity directory: {APP_DIR}")
    print(f"Server running on http://127.0.0.1:{port}")
    
    if AUTO_LOGIN_ENABLED:
        print("Auto-login enabled from CLI")
    
    if not args.no_browser:
        print("Opening browser...")
        webbrowser.open(f'http://127.0.0.1:{port}')
    
    socketio.run(app, host='127.0.0.1', port=port, debug=False)
