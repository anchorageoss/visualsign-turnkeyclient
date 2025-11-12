# Tropic Square TROPIC01 Integration Plan

## Overview

This document outlines the plan for integrating the verification code with Tropic Square's TROPIC01 secure element for hardware-accelerated cryptographic verification.

## Current Status

### Research Findings

**Tropic Square TROPIC01 Specifications:**
- **CPU:** RISC-V IBEX core (32-bit, RV32IMC instruction set)
- **Hardware Crypto:** P-256 ECDSA, Ed25519, X25519 acceleration
- **Memory:** OTP for certificates/keys, Flash for data (exact sizes not publicly disclosed)
- **Security:** Tamper-proof, voltage fault detection, EM pulse detection, laser intrusion detection
- **SDK:** libtropic (C), libtropic-rs (Rust)

**SDK Repository Status:**
- Documentation: ✅ Available (PDFs in [tropic01 repo](https://github.com/tropicsquare/tropic01))
- libtropic SDK: ⚠️  Private/Not yet published
- libtropic-linux: ⚠️  Private/Not yet published
- libtropic-stm32: ⚠️  Private/Not yet published

**Note:** Tropic Square is gradually publishing their repositories. Check [GitHub](https://github.com/tropicsquare) for updates.

### TinyGo Compatibility Results

✅ **Successfully compiled verification code for 32-bit RISC-V:**
- Basic crypto test: 4.6MB binary
- Full verification stack: 3.1MB binary
- All dependencies compile (crypto/x509, CBOR, Borsh)
- Bare-metal execution model matches Tropic Square's requirements

⚠️  **Binary size likely too large for secure element:**
- Typical secure elements: 512KB - 2MB flash
- Our full verification: 3.1MB
- **Solution:** Use hardware crypto + minimal verification logic

## Integration Approach

### Recommended: Hardware-Accelerated Minimal Verification

Instead of running the full 3.1MB verification stack on Tropic Square, leverage its hardware crypto:

**Architecture:**
```
┌─────────────────┐
│  Server/PC      │
│  (Full Go)      │
│                 │
│  - Parse CBOR   │
│  - Validate     │
│    cert chain   │
│  - Extract:     │
│    • publicKey  │
│    • signature  │
│    • message    │
└────────┬────────┘
         │
         │ (simplified data)
         ▼
┌─────────────────┐
│  Tropic Square  │
│  TROPIC01       │
│                 │
│  - HW P-256     │
│  - Verify sig   │
│  - Return OK    │
└─────────────────┘
```

**Benefits:**
- **Small code size** (~50-100KB instead of 3.1MB)
- **Hardware acceleration** (faster, lower power)
- **Fits in secure element memory**
- **Maximum security** (crypto in tamper-proof hardware)

## Implementation Steps

### Phase 1: SDK Access & Examples (BLOCKED)

**Status:** ⏸️ Waiting for SDK publication

**Required:**
1. Wait for libtropic SDK to be published
2. Or contact Tropic Square for early access
3. Study API documentation (PDFs available in [tropic01 doc/api/](https://github.com/tropicsquare/tropic01/tree/main/doc/api))
4. Review example code when available

**Alternative:**
- Read API documentation PDFs directly
- Contact Tropic Square: https://tropicsquare.com/tropic01

### Phase 2: CGo Bridge to libtropic

Create a Go wrapper around the C libtropic SDK:

**File Structure:**
```
pkg/
  tropicsquare/
    libtropic.go      # Go interface
    libtropic_cgo.go  # CGo bindings
    types.go          # Type definitions
cmd/
  tropicsquare-test/
    main.go           # Test program
```

**Example Interface** (pseudo-code, actual API TBD):
```go
package tropicsquare

// #cgo LDFLAGS: -ltropic
// #include <libtropic.h>
import "C"

type TropicSquare struct {
    handle C.lt_handle_t
}

func New() (*TropicSquare, error) {
    // Initialize libtropic
}

func (ts *TropicSquare) VerifyECDSA_P256(
    publicKey []byte,
    message []byte,
    signature []byte,
) (bool, error) {
    // Call hardware P-256 ECDSA verification
    // via libtropic C functions
}

func (ts *TropicSquare) Close() error {
    // Cleanup
}
```

### Phase 3: Minimal Verification Service

Create a minimal verification service that uses Tropic Square hardware:

```go
package tropicsquare

import (
    "crypto/sha256"
    "fmt"
)

// MinimalVerifier uses Tropic Square hardware for verification
type MinimalVerifier struct {
    device *TropicSquare
}

func NewMinimalVerifier() (*MinimalVerifier, error) {
    device, err := New()
    if err != nil {
        return nil, fmt.Errorf("failed to initialize Tropic Square: %w", err)
    }
    return &MinimalVerifier{device: device}, nil
}

// VerifyAttestation verifies pre-processed attestation data
// Input data should be extracted from full attestation by a server
func (v *MinimalVerifier) VerifyAttestation(
    publicKey []byte,     // 65-byte uncompressed P-256 public key
    message []byte,       // Message to verify
    signature []byte,     // 64-byte signature (r||s)
) error {
    // Hash the message
    hash := sha256.Sum256(message)

    // Use hardware verification
    valid, err := v.device.VerifyECDSA_P256(publicKey, hash[:], signature)
    if err != nil {
        return fmt.Errorf("verification failed: %w", err)
    }

    if !valid {
        return fmt.Errorf("signature verification failed")
    }

    return nil
}

func (v *MinimalVerifier) Close() error {
    return v.device.Close()
}
```

### Phase 4: Server-Side Pre-processing

The server handles the heavy lifting:

```go
package server

import (
    "github.com/anchorageoss/visualsign-turnkeyclient/verify"
)

// PreprocessAttestation extracts verification data for Tropic Square
func PreprocessAttestation(
    attestationDoc string,
    manifestB64 string,
) (*TropicSquareVerificationData, error) {
    // Use existing full verification service
    service := verify.NewService(...)

    // Perform full verification on server
    result, err := service.Verify(ctx, request)
    if err != nil {
        return nil, err
    }

    // Extract only what Tropic Square needs
    return &TropicSquareVerificationData{
        PublicKey: result.PublicKey,
        Message:   result.MessageHex,
        Signature: result.SignatureHex,
        // Optionally include manifest hash for additional verification
        ManifestHash: result.QosManifestHash,
    }, nil
}

type TropicSquareVerificationData struct {
    PublicKey    []byte `json:"publicKey"`
    Message      []byte `json:"message"`
    Signature    []byte `json:"signature"`
    ManifestHash string `json:"manifestHash"`
}
```

### Phase 5: End-to-End Testing

Test the integration:
1. Full verification on server
2. Data extraction
3. Transfer to Tropic Square device
4. Hardware verification
5. Compare results

## Alternative Approaches

### Option A: TinyGo on Tropic Square (Experimental)

**Attempt to run TinyGo-compiled verification code:**

**Pros:**
- Full verification on-device
- No server pre-processing needed
- Maximum security

**Cons:**
- 3.1MB binary likely too large
- Unknown memory requirements
- Untested runtime behavior (CBOR/Borsh reflection)

**Status:** Feasibility depends on:
- Exact flash/RAM size of Tropic Square
- Whether full binary can fit
- Runtime testing needed

### Option B: Hybrid Approach

**Use TinyGo for logic, libtropic for crypto:**

Compile minimal verification logic with TinyGo, but call out to libtropic for hardware crypto operations via FFI.

**Pros:**
- Go code for business logic
- Hardware acceleration for crypto
- Smaller binary than full verification

**Cons:**
- Complex FFI/interop
- TinyGo CGo limitations
- More testing required

## Next Steps

### Immediate Actions

1. **Obtain SDK Access**
   - Check if libtropic is now public: https://github.com/tropicsquare/libtropic
   - If private, request access from Tropic Square
   - Alternative: Read API PDFs and implement based on documentation

2. **Study API Documentation**
   - Review API PDFs in `/tmp/tropic01-main/doc/api/`
   - Identify exact function signatures for:
     - ECDSA P-256 verification
     - Device initialization
     - Key management
     - Error handling

3. **Get Hardware**
   - Order TROPIC01 development board
   - Options: Arduino Shield, Raspberry Pi Shield, USB stick
   - See: https://tropicsquare.com/tropic01

### Development Tasks

**When SDK becomes available:**

1. Create `pkg/tropicsquare/` package with CGo bindings
2. Implement `MinimalVerifier` interface
3. Write unit tests with mock hardware
4. Create integration tests with actual device
5. Benchmark performance vs software verification
6. Document memory usage and power consumption

**Separate PR/Branch:**
- Keep Tropic Square integration separate from TinyGo compatibility work
- Branch name: `feat/tropicsquare-integration`
- Merge after thorough testing on actual hardware

## Resources

### Documentation

- **Tropic Square Website:** https://tropicsquare.com/tropic01
- **GitHub Organization:** https://github.com/tropicsquare
- **Product Documentation:** https://github.com/tropicsquare/tropic01
- **API Documentation:** `/tmp/tropic01-main/doc/api/ODU_TR01_user_api_v1.3.0.pdf`
- **Datasheet:** `/tmp/tropic01-main/doc/datasheet/ODD_TR01_datasheet_revA9.pdf`

### Related Work

- **TinyGo Compatibility Report:** `TINYGO_COMPATIBILITY_REPORT.md`
- **Verification Service:** `verify/service.go`
- **Manifest Handling:** `manifest/`
- **Crypto Operations:** `crypto/signing.go`

### Development Boards

- Arduino Shield: https://github.com/tropicsquare/tropic01-arduino-shield-hw
- Raspberry Pi Shield: https://github.com/tropicsquare/tropic01-raspberrypi-shield-hw
- USB Stick (STM32U5): https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-hw

## Questions for Tropic Square

Before full integration, clarify:

1. **Memory Specifications**
   - Exact flash size available for user code?
   - RAM available at runtime?
   - OTP size for certificates?

2. **API Details**
   - Is libtropic SDK publicly available?
   - If not, when is expected release?
   - Can we get early access for integration?

3. **ECDSA P-256 API**
   - Function signature for signature verification?
   - Input format (raw r||s or DER encoded)?
   - Hash computation (on-device or pre-hashed)?

4. **Development Support**
   - Recommended development board for testing?
   - Example projects available?
   - Community/support channels?

## Conclusion

**Recommended Path Forward:**

1. ✅ **Completed:** TinyGo RISC-V compatibility testing
2. ⏸️  **Blocked:** Waiting for libtropic SDK publication
3. 🎯 **Next:** Obtain SDK access and hardware
4. 🔨 **Then:** Implement minimal hardware-accelerated verification

**Timeline Estimate:**
- SDK access: TBD (depends on Tropic Square)
- Initial integration: 1-2 weeks (once SDK available)
- Testing & validation: 2-3 weeks
- Production-ready: 1-2 months

**Success Criteria:**
- Successful P-256 ECDSA verification on hardware
- Code size < 100KB
- Verification time < 100ms
- Compatible with existing attestation format
