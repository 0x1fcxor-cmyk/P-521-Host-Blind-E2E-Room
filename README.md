# P-521 Host-Blind E2E Room

A secure, end-to-end encrypted communication system using P-521 elliptic curve cryptography with a host-blind relay architecture.

## Features

- **P-521 Elliptic Curve Cryptography** - High-security 521-bit curve for identity keys
- **Argon2id Key Derivation** - Memory-hard password-based key derivation
- **AES-256-GCM Encryption** - Authenticated encryption for message content
- **Host-Blind Relay** - Relay server cannot decrypt room messages
- **E2E Invite System** - Secure room key distribution via invite links
- **Sealed Sender Mode** - Optional sender anonymity
- **Web UI** - Modern, responsive web interface with glassmorphism design
- **CLI Interface** - Full-featured command-line interface
- **Trust Management** - Contact verification and trust-on-first-use model

## Security Architecture

### Cryptographic Components

- **Identity Keys**: P-521 ECDSA for digital signatures
- **Room Keys**: 256-bit symmetric keys for E2E encryption
- **Key Derivation**: Argon2id (time_cost=3, memory_cost=256MB, parallelism=4)
- **Message Encryption**: AES-256-GCM with authenticated encryption
- **Fingerprints**: SHA-256 hash of public key DER format

### Host-Blind Model

The relay server operates in a "blind" mode where it:
- Routes encrypted envelopes between participants
- Cannot decrypt room keys (stored in URL fragment)
- Cannot read message content
- Only sees metadata: IP addresses, timing, packet sizes, room IDs, fingerprints

### Security Limitations

- **Relay Metadata**: The relay sees IP addresses, timing, packet sizes, room IDs, and fingerprints
- **Invite Links**: Room keys are included in invite links - protect them carefully
- **TOFU Trust**: Trust-on-first-use model - verify fingerprints out-of-band
- **No Formal Protocol**: Lacks formal protocol transcript or HKDF key schedule
- **Message Persistence**: SQLite database may store message metadata in plaintext

## Installation

### Requirements

- Python 3.10+
- pip

### Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install cryptography argon2-cffi flask flask-socketio websockets
```

## Usage

### CLI Interface

```bash
python main.py
```

The CLI provides options for:
- Hosting a blind relay with Cloudflare tunnel
- Joining E2E rooms
- Generating E2E invite links
- Managing identities
- Trust management
- Settings configuration

### Web UI

```bash
python web_ui.py
```

The web UI provides a modern interface with:
- Identity creation and login
- Room management
- Real-time chat
- File sharing
- Emoji reactions
- Message search
- Dark mode support

### Running a Portable Relay Server

For users who need a WebSocket relay server, a portable standalone relay is included:

```bash
# Generate a secure token
python run_relay.py --generate-token

# Start the relay server with a custom token
python run_relay.py --token YOUR_SECRET_TOKEN --port 8080

# Start on all interfaces (for remote access)
python run_relay.py --token YOUR_SECRET_TOKEN --host 0.0.0.0 --port 8080

# Start with Cloudflare tunnel for public access (no port forwarding needed)
python run_relay.py --token YOUR_SECRET_TOKEN --cloudflare

# Start with default settings (generates random token)
python run_relay.py
```

The relay server:
- Cannot decrypt E2E encrypted content (blind relay)
- Supports up to 100 concurrent clients (configurable)
- Includes rate limiting (100 messages per 60 seconds per client)
- Provides health monitoring and statistics
- Requires authentication via token
- Optional Cloudflare tunnel for public hosting

**Cloudflare Tunnel for Public Hosting:**

To make your relay server publicly accessible without port forwarding, use the `--cloudflare` flag. This requires `cloudflared` to be installed:

1. Install cloudflared from [Cloudflare's installation guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/)
2. Run the relay with Cloudflare tunnel:
   ```bash
   python run_relay.py --token YOUR_TOKEN --cloudflare
   ```
3. The server will display a public URL that anyone can use to connect

Once running, use the relay URL in the web UI or CLI:
```
ws://your-host:port/chat?token=YOUR_TOKEN
# Or with Cloudflare tunnel:
https://your-cloudflare-url/chat?token=YOUR_TOKEN
```

### Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
e2e/
├── client/              # Client-side room handling
├── core/                # Core cryptographic functions
├── identity/            # Identity and key management
├── protocol/            # Protocol implementation
├── relay/               # Relay server implementation
├── storage/             # Encrypted storage
├── transport/           # Transport layer (Cloudflare)
├── templates/           # Web UI HTML templates
├── static/              # Web UI static assets
├── tests/               # Unit tests
├── main.py              # CLI entry point
├── web_ui.py            # Web UI server
├── run_relay.py         # Portable WebSocket relay server
└── 0x1FC_p-521_E2E_SecureComs.py  # Core crypto module
```

## Configuration

### Environment Variables

- `P521_AUTO_PASSWORD` - Auto-login password for web UI
- `P521_AUTO_FINGERPRINT` - Auto-login fingerprint
- `P521_AUTO_DISPLAY_NAME` - Auto-login display name
- `P521_AUTO_INVITE_LINK` - Auto-join room on web UI start
- `P521_WEB_UI_PORT` - Web UI server port
- `P521_LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

### Storage

All data is stored in `~/.p521_host_blind_room/`:
- `identity.enc` - Encrypted private key
- `public.pem` - Public key
- `storage_salt.bin` - Storage key derivation salt
- `settings.enc` - Encrypted settings
- `trust.enc` - Encrypted trust store
- `logs/` - Application logs
- `downloads/` - Downloaded files

## Protocol Version

`P521-HOST-BLIND-E2E-V1`

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure all tests pass before submitting PRs.

## Security Audit

This project has not undergone a formal security audit. Use at your own risk for sensitive communications.
