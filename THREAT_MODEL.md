# Threat Model: P-521 Host-Blind E2E Room

## Current Implementation Status

**This is a prototype with known security limitations.** It is not suitable for high-threat environments without significant protocol redesign.

## What We Defend Against

### Active Defenses
- **Relay content blindness**: The relay cannot decrypt message bodies (E2E encrypted with room key)
- **Message authentication**: All messages are signed with P-521 ECDSA-SHA512
- **Replay protection**: Message counters prevent replay attacks
- **Identity verification**: Fingerprint-based trust model with change warnings
- **Local storage encryption**: Identity, settings, and trust data encrypted at rest

### Partial Defenses
- **Passive network observers**: Cannot read message content due to E2E encryption
- **Relay operators**: Cannot read message content, but see metadata
- **Compromised local storage**: Protected by Argon2id password hardening (if argon2-cffi installed)

## What We Do NOT Defend Against

### Known Limitations
- **Relay metadata exposure**: The relay sees:
  - IP addresses of all participants
  - Connection timing patterns
  - Packet sizes
  - Room IDs
  - Public keys/fingerprints
  - Connection counts

- **Invite link compromise**: Room keys are included in invite links. Anyone with the link can decrypt all room messages.

- **No forward secrecy**: Compromise of the room key allows decryption of all past and future messages in that room.

- **No group membership control**: Access is based solely on possession of the room key. No member revocation or key rotation.

- **Local metadata in plaintext**: SQLite database stores message metadata (sender_fp, room_id, timestamps) in plaintext.

- **Audit log exposure**: Some audit logs may be written in plaintext if identity is not available.

- **No formal protocol**: Lacks formal protocol transcript, HKDF-based key schedule, or standardized handshake.

- **Cloudflare Tunnel metadata**: When using Cloudflare tunnels, Cloudflare sees connection metadata.

### Not Defended Against (by design)
- **Compromised endpoint**: If the user's device is compromised, all security guarantees fail
- **Screen recording/keyloggers**: Cannot protect against local malware
- **Malicious recipient**: Recipients can share received messages
- **User error**: Users sharing room keys or invite links
- **Traffic correlation**: Timing analysis could reveal communication patterns
- **OS-level malware**: Cannot protect against rootkits or similar threats

## Threat Actors

### Low-Skill Threats
- **Casual snoopers**: Protected by E2E encryption
- **Opportunistic attackers**: Protected by signatures and replay protection

### Medium-Skill Threats
- **Network-level attackers**: Partially protected (content encrypted, metadata visible)
- **Relay operators**: Content protected, metadata visible
- **Local storage thieves**: Protected by Argon2id password hardening

### High-Skill Threats
- **State-level actors**: NOT protected against
- **Persistent malware**: NOT protected against
- **Advanced traffic analysis**: NOT protected against

## Required for "Serious-Grade" Security

The following would be required for this to be suitable for high-threat environments:

### Protocol Level
1. **Formal handshake protocol**: Use X3DH (Signal Protocol) or Noise Protocol Framework
2. **Proper forward secrecy**: Implement Double Ratchet or similar ratcheting mechanism
3. **HKDF-based key schedule**: Use labeled HKDF for all key derivation
4. **Transcript hash binding**: Bind handshake components to prevent context switching
5. **Sealed sender mode**: Encrypt sender identity to reduce relay metadata

### Group Security
1. **Room epochs**: Versioned room keys with rotation on member changes
2. **Member revocation**: Ability to remove members and rotate keys
3. **Signed invites**: Authenticated, expiring, single-use invite tokens
4. **MLS-style architecture**: Consider Messaging Layer Security for group chat

### Storage Security
1. **Encrypted database**: Use SQLCipher or application-layer encryption for all data
2. **No plaintext metadata**: Hash or encrypt all stored identifiers
3. **Encrypted logs**: Enforce encrypted logging for all audit events
4. **Secure deletion**: Provide best-effort secure deletion options

### Transport Security
1. **Multiple relay options**: Support Tor, WireGuard, LAN-only modes
2. **Transport labeling**: Clearly label privacy vs convenience modes
3. **Metadata minimization**: Reduce what relays can see

### Engineering Practices
1. **Codebase separation**: Split into protocol/relay/client/storage modules
2. **Test vectors**: Deterministic test vectors for protocol verification
3. **Fuzz testing**: Fuzz parsers and decrypt paths
4. **Dependency pinning**: Use pinned, hash-locked dependencies
5. **Reproducible builds**: Enable reproducible builds
6. **External audit**: Third-party security audit
7. **Memory safety**: Consider Rust/Go for crypto core

### User Experience
1. **Fingerprint verification**: QR codes, SAS, emoji fingerprints
2. **Security modes**: Standard/Hardened/Paranoid modes
3. **Clear threat model**: Document what is and isn't protected
4. **No silent downgrades**: Hard fail on crypto failures
5. **Key backup**: Encrypted identity export and recovery

## Current Risk Assessment

**Risk Level: MEDIUM**

Suitable for:
- Casual private communication
- Low-threat environments
- Prototyping and development
- Learning about E2E encryption concepts

NOT suitable for:
- High-threat environments
- Political activism in repressive regimes
- Protecting sensitive business data
- Whistleblowing
- Journalism with sensitive sources

## Migration Path

To achieve serious-grade security, the recommended path is:

1. **Phase 1**: Fix critical crypto issues (Argon2id, HKDF, remove broken PFS)
2. **Phase 2**: Implement proper handshake (X3DH or Noise)
3. **Phase 3**: Add Double Ratchet for forward secrecy
4. **Phase 4**: Implement room epochs and member management
5. **Phase 5**: Add sealed sender and metadata minimization
6. **Phase 6**: Multiple transport options (Tor, WireGuard)
7. **Phase 7**: Codebase modularization and testing
8. **Phase 8**: External audit and formal verification

This is a multi-month effort requiring protocol design expertise.

## Disclaimer

This software is provided as-is for educational and prototyping purposes. The authors make no security guarantees. Users should understand the limitations documented in this threat model before using it for sensitive communications.
