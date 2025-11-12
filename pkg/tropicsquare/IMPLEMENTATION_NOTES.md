# Tropic Square Implementation Notes

## Current Implementation: Verification Only (Pure Go)

This package provides **ECDSA P-256 signature verification** for attestation documents using Go's standard library (`crypto/ecdsa`).

**✅ No TROPIC01 hardware required**
**✅ No libtropic SDK required**
**✅ No CGo complexity**
**✅ Works with TinyGo/RISC-V**

## When Do You Need libtropic SDK?

The libtropic SDK is **NOT needed for verification**. It's only needed for these use cases:

### Hardware Wallet / Signing Operations

```
┌─────────────────────────────┐
│   Use Case: Hardware Wallet │
│   Needs: libtropic SDK      │
└─────────────────────────────┘

Operations requiring SDK:
✅ Sign with hardware keys (lt_ecc_ecdsa_sign)
✅ Generate keys in secure storage
✅ Store private keys in TROPIC01 slots
✅ Hardware RNG (lt_random)
✅ Secure session management
✅ Firmware updates
✅ Key provisioning
```

### Attestation Verification (Our Use Case)

```
┌──────────────────────────────┐
│   Use Case: Verification     │
│   Needs: Pure Go (this pkg)  │
└──────────────────────────────┘

Operations using pure Go:
✅ Verify ECDSA signatures
✅ Validate attestation documents
✅ Check message integrity
✅ Runs anywhere (no hardware)
```

## Why libtropic Verification is Software-Based

From libtropic source code:

```c
// libtropic/include/libtropic.h
/**
 * @brief Verifies ECDSA signature. Host side only, does not require TROPIC01.
 */
lt_ret_t lt_ecc_ecdsa_sig_verify(const uint8_t *msg, const uint32_t msg_len,
                                  const uint8_t *pubkey, const uint8_t *rs);
```

**Key phrase:** "Host side only, does not require TROPIC01"

The function is a wrapper around trezor-crypto (excellent library, but software-based). Using it via CGo would add build complexity for zero benefit.

## Implementation

### device_purego.go (Current, Recommended)

```go
// Pure Go implementation using crypto/ecdsa
func (d *Device) VerifyECDSA_P256(publicKey, hash, signature []byte) (bool, error) {
    curve := elliptic.P256()
    x := new(big.Int).SetBytes(publicKey[:32])
    y := new(big.Int).SetBytes(publicKey[32:])

    pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
    r := new(big.Int).SetBytes(signature[:32])
    s := new(big.Int).SetBytes(signature[32:])

    return ecdsa.Verify(pubKey, hash, r, s), nil
}
```

**Benefits:**
- No external dependencies
- Fast compilation
- Cross-platform (including TinyGo/RISC-V)
- Same cryptographic security as libtropic/trezor-crypto
- Tested and working

## Future: Hardware Wallet Example

If you want to build a hardware wallet that DOES use TROPIC01 for signing, see the planned example:

```
examples/
  hardware-wallet/          (future)
    ├── README.md           # When/why to use TROPIC01
    ├── sign.go             # Uses libtropic SDK for signing
    ├── verify.go           # Uses this package for verification
    └── integration.md      # Full SDK integration guide
```

That example would show:
- Device initialization with libtropic
- Secure session establishment
- Key generation and storage in TROPIC01
- Hardware-accelerated signing
- Software verification (using this package)

## Building

### Current Implementation (Pure Go)
```bash
# Default build - pure Go verification
go build ./pkg/tropicsquare

# Works with TinyGo too
tinygo build -target=riscv-qemu ./pkg/tropicsquare
```

### If You Need Hardware Signing (Future)
```bash
# Would require libtropic SDK, CGo, trezor-crypto
# See examples/hardware-wallet/ (when created)
```

## Testing

```bash
go test ./pkg/tropicsquare
```

## API

```go
// MinimalVerifier provides attestation verification
type MinimalVerifier struct {
    device *Device
}

// NewMinimalVerifier creates a verifier (no hardware needed)
func NewMinimalVerifier() (*MinimalVerifier, error)

// VerifyAttestation verifies signature with public key
// publicKey: 64 or 65 bytes (0x04 prefix stripped if present)
// message: The signed message
// signature: 64 bytes (r || s)
func (v *MinimalVerifier) VerifyAttestation(
    publicKey, message, signature []byte,
) error
```

## Design Philosophy

### Separation of Concerns

| Component | Purpose | Dependencies |
|-----------|---------|--------------|
| **This Package** | Verify signatures | `crypto/ecdsa` (stdlib) |
| **Future HW Wallet** | Sign with hardware keys | libtropic SDK + TROPIC01 |

### Why This Makes Sense

1. **Verification** = Public operation, can run anywhere
   - On servers validating attestations
   - On embedded devices checking signatures
   - In TinyGo/RISC-V firmware
   - No secrets involved

2. **Signing** = Private operation, needs secure storage
   - Keys must never leave TROPIC01
   - Hardware tamper protection
   - Secure element features
   - Requires physical device

## Summary

**For attestation verification (current use case):**
- ✅ Use this package (pure Go)
- ❌ Don't use libtropic SDK (adds complexity for zero benefit)

**For hardware wallet / signing:**
- See planned `examples/hardware-wallet/`
- That example will show full libtropic integration
- Separate from verification (different use case)

**Both approaches are valid** - just for different purposes!
