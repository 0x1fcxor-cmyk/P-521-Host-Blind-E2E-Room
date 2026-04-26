# Test Vectors

This directory contains deterministic test vectors for protocol verification.

## Purpose

Test vectors provide:
- Deterministic inputs and expected outputs
- Verification that protocol changes don't break existing behavior
- Reference implementations can validate against these vectors
- Security audits can verify protocol correctness

## Test Vector Format

Each test vector is a JSON file with the following structure:

```json
{
  "test_id": "unique_identifier",
  "description": "Human-readable description",
  "protocol_version": "P521-HOST-BLIND-E2E-V1",
  "inputs": {
    // Input parameters for the test
  },
  "expected": {
    // Expected outputs
  },
  "notes": [
    // Additional context and explanations
  ]
}
```

## Current Test Vectors

### envelope_encrypt_001.json
Tests envelope encryption with room key using AES-256-GCM.

### signature_verify_001.json
Tests P-521 ECDSA signature verification on envelopes.

### replay_reject_001.json
Tests replay protection with duplicate message counters.

### hkdf_derive_001.json
Tests HKDF-SHA512 key derivation with labeled contexts.

### storage_key_derive_001.json
Tests storage key derivation with Argon2id password hardening.

## Using Test Vectors

### Manual Verification

1. Parse the test vector JSON
2. Extract inputs
3. Run the cryptographic operation
4. Compare output with expected values
5. Verify all notes are satisfied

### Automated Testing

A test runner should:
1. Load all test vectors from this directory
2. For each vector:
   - Parse inputs
   - Execute the operation
   - Compare with expected outputs
   - Report pass/fail
3. Generate a report with results

### Adding New Test Vectors

When adding new test vectors:
1. Use a unique test_id (increment the number)
2. Provide clear description
3. Include all necessary inputs
4. Specify expected outputs precisely
5. Add notes explaining the test purpose
6. Update this README

## Test Vector Categories

### Cryptographic Operations
- Key derivation (HKDF, Argon2id)
- Encryption/decryption (AES-256-GCM)
- Signature generation/verification (P-521 ECDSA)

### Protocol Operations
- Envelope creation and parsing
- Replay protection
- Message deduplication
- Counter management

### Edge Cases
- Invalid signatures
- Replay attempts
- Malformed envelopes
- Counter overflow
- Nonce reuse

## Security Considerations

- Test vectors should not contain real private keys
- Use deterministic test keys only
- Do not include production credentials
- Test vectors are public and can be audited

## Future Test Vectors

Planned additions:
- Handshake protocol vectors (X3DH/Noise)
- Double Ratchet vectors
- Room epoch rotation vectors
- Signed invite token vectors
- Sealed sender vectors
- File transfer vectors

## References

- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Signal Protocol Test Vectors](https://github.com/signalapp/libsignal-protocol-java/tree/master/tests)
- [Noise Protocol Framework Test Vectors](https://github.com/noiseprotocol/noise_wiki/wiki/Test-Vectors)
