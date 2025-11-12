# Hardware Wallet Communication Protocol

## Overview

This document defines the communication protocol between the RISC-V verifier board and the TROPIC01 secure element.

**Transport:** SPI or UART
**Byte Order:** Little Endian
**Frame Format:** Binary (no text encoding)

## Message Structure

All messages follow this structure:

```
┌──────────┬─────────────┬─────────┬─────────────┐
│ Command  │ Parameters  │ Padding │   Payload   │
│ (1 byte) │ (variable)  │ (align) │  (variable) │
└──────────┴─────────────┴─────────┴─────────────┘
```

### Response Structure

```
┌──────────┬──────────┬─────────┬──────────────┐
│  Status  │ Reserved │ Padding │   Payload    │
│ (1 byte) │ (3 bytes)│ (align) │  (variable)  │
└──────────┴──────────┴─────────┴──────────────┘
```

## Commands

### 0x01 - GET_INFO

Retrieve chip ID and firmware versions.

**Request:**
```
Byte  | Field      | Description
------|------------|-------------
0     | Command    | 0x01
1-3   | Reserved   | 0x00
```

**Response:**
```
Byte  | Field          | Description
------|----------------|---------------------------
0     | Status         | 0x00 = success
1-3   | Reserved       | 0x00
4-19  | Chip ID        | 16-byte unique identifier
20-23 | FW Version     | Major.Minor.Patch.Build
24-27 | SPECT Version  | Major.Minor.Patch.Build
```

**Example:**
```
Request:  01 00 00 00
Response: 00 00 00 00 [16 bytes chip ID] 01 00 00 00 01 00 00 00
          └─ OK        └─ FW 1.0.0.0     └─ SPECT 1.0.0.0
```

### 0x02 - SIGN

Sign a message hash with a specific key slot.

**Request:**
```
Byte  | Field      | Description
------|------------|-----------------------------------
0     | Command    | 0x02
1     | Key Slot   | 0-31 (ECC key slot)
2-3   | Reserved   | 0x00
4-35  | Hash       | 32-byte SHA256 hash to sign
```

**Response:**
```
Byte    | Field          | Description
--------|----------------|---------------------------
0       | Status         | 0x00 = success
1-3     | Reserved       | 0x00
4-67    | Signature      | 64 bytes (r || s)
        |                | - r: bytes 4-35 (32 bytes)
        |                | - s: bytes 36-67 (32 bytes)
68-131  | Public Key     | 64 bytes (X || Y)
        |                | - X: bytes 68-99 (32 bytes)
        |                | - Y: bytes 100-131 (32 bytes)
```

**Example:**
```
Request:  02 00 00 00 [32 bytes hash]
Response: 00 00 00 00 [64 bytes sig] [64 bytes pubkey]
```

**Status Codes:**
- `0x00` - Success
- `0x02` - Invalid key slot
- `0x03` - Signing error (key not found, hardware error, etc.)

### 0x03 - GET_PUBKEY

Retrieve public key for a key slot without signing.

**Request:**
```
Byte  | Field      | Description
------|------------|-----------------------------------
0     | Command    | 0x03
1     | Key Slot   | 0-31 (ECC key slot)
2-3   | Reserved   | 0x00
```

**Response:**
```
Byte   | Field          | Description
-------|----------------|---------------------------
0      | Status         | 0x00 = success
1-3    | Reserved       | 0x00
4-67   | Public Key     | 64 bytes (X || Y)
```

### 0x04 - GENERATE_KEY

Generate a new key pair in a specific slot.

**Request:**
```
Byte  | Field      | Description
------|------------|-----------------------------------
0     | Command    | 0x04
1     | Key Slot   | 0-31 (ECC key slot)
2-3   | Reserved   | 0x00
```

**Response:**
```
Byte   | Field          | Description
-------|----------------|---------------------------
0      | Status         | 0x00 = success
1-3    | Reserved       | 0x00
4-67   | Public Key     | 64 bytes (X || Y) of new key
```

**Note:** Private key stays in TROPIC01, only public key is returned.

## Status Codes

| Code | Name                | Description                       |
|------|---------------------|-----------------------------------|
| 0x00 | STATUS_OK           | Operation successful              |
| 0x01 | STATUS_INVALID_CMD  | Unknown command                   |
| 0x02 | STATUS_INVALID_SLOT | Invalid key slot (must be 0-31)   |
| 0x03 | STATUS_SIGNING_ERROR| Hardware signing failed           |
| 0x04 | STATUS_NO_SESSION   | Secure session not established    |
| 0x05 | STATUS_TIMEOUT      | Operation timed out               |
| 0xFF | STATUS_FATAL_ERROR  | Unrecoverable error               |

## Transport Layer

### SPI Configuration
- **Mode:** Mode 0 (CPOL=0, CPHA=0)
- **Speed:** Up to 10 MHz
- **Bits:** 8 bits per word
- **CS:** Active low

**Pinout:**
- MOSI: RISC-V → TROPIC01
- MISO: TROPIC01 → RISC-V
- SCK: Clock from RISC-V
- CS: Chip select (active low)

### UART Configuration
- **Baud Rate:** 115200
- **Data Bits:** 8
- **Parity:** None
- **Stop Bits:** 1
- **Flow Control:** None

## Security Considerations

### Message Authentication
For production use, add HMAC to prevent tampering:

```
┌──────────┬────────────┬─────────┬──────┐
│  Header  │  Payload   │  HMAC   │ CRC  │
│ (4 bytes)│ (variable) │(32 bytes)│(2 b) │
└──────────┴────────────┴─────────┴──────┘
```

### Replay Protection
Add a nonce/counter to prevent replay attacks:

```
Request:
┌──────────┬─────────┬─────────────┐
│ Command  │  Nonce  │   Payload   │
│ (1 byte) │(8 bytes)│  (variable) │
└──────────┴─────────┴─────────────┘
```

TROPIC01 maintains counter and rejects old nonces.

### Secure Session
Use libtropic's secure session protocol for encrypted communication:

1. RISC-V establishes secure session with TROPIC01
2. All subsequent messages are encrypted
3. Session key derived from pairing key
4. Forward secrecy with ECDH

## Implementation

### RISC-V Side (Go)

See `riscv-verifier/tropic01_signer.go`

Key functions:
- `NewTROPIC01Signer(devicePath)` - Initialize
- `Sign(keySlot, hash)` - Request signature
- `GetPublicKey(keySlot)` - Get public key
- `GetDeviceInfo()` - Get chip info

### TROPIC01 Side (C + libtropic)

See `tropic01-signer/src/protocol.c` (to be implemented)

Key functions:
```c
// Initialize protocol handler
void protocol_init(void);

// Process incoming command
void protocol_handle_command(uint8_t *cmd, size_t len,
                            uint8_t *response, size_t *resp_len);

// Sign with key slot
int protocol_sign(uint8_t slot, const uint8_t *hash,
                 uint8_t *signature, uint8_t *pubkey);
```

Uses libtropic SDK:
- `lt_init()` - Initialize TROPIC01
- `lt_ecc_ecdsa_sign()` - Hardware signing
- `lt_verify_chip_and_start_secure_session()` - Secure session

## Testing

### Unit Tests
Test each command with known inputs/outputs:

```bash
# Test GET_INFO
echo "01 00 00 00" | xxd -r -p | spi-tool /dev/spidev0.0

# Test SIGN (with test vectors)
echo "02 00 00 00 [hash]" | xxd -r -p | spi-tool /dev/spidev0.0
```

### Integration Tests
Full flow tests:

```bash
# Sign and verify
./test_sign_verify.sh

# Key generation
./test_keygen.sh

# Error handling
./test_errors.sh
```

## Performance

Typical operation times (at 10 MHz SPI):

| Operation    | Time   | Notes                          |
|--------------|--------|--------------------------------|
| GET_INFO     | ~2ms   | Fast, no crypto                |
| SIGN         | ~50ms  | ECDSA signing in hardware      |
| GET_PUBKEY   | ~10ms  | Read from storage              |
| GENERATE_KEY | ~100ms | Generates key pair with HW RNG |

## Error Recovery

### Timeouts
- RISC-V timeout: 1 second per command
- TROPIC01 timeout: 500ms per operation
- On timeout: Retry up to 3 times

### Connection Loss
- RISC-V detects: No response or garbled data
- Recovery: Reset connection, re-establish session
- User notification: "Reconnecting to secure element..."

### Fatal Errors
- Hardware failure detection
- TROPIC01 tamper detection triggered
- Action: Lock device, require user reset

## Future Enhancements

1. **Batch Operations**
   - Sign multiple transactions in one command
   - Reduce round-trip latency

2. **Attestation**
   - TROPIC01 provides attestation of firmware
   - RISC-V verifies before trusting signatures

3. **Display Verification**
   - TROPIC01 has its own display
   - Shows transaction independently
   - Prevents display substitution attacks

4. **Biometric Auth**
   - Fingerprint sensor on RISC-V
   - Unlock TROPIC01 operations
   - Additional security layer
