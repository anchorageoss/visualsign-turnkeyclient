# Tropic Square Integration Package

This package provides integration with Tropic Square TROPIC01 secure element for hardware-accelerated cryptographic verification.

## Status

⚠️ **Work In Progress** - Waiting for libtropic SDK publication

## Prerequisites

- libtropic SDK (not yet publicly available)
- Tropic Square TROPIC01 hardware
- Development board (Arduino Shield, Raspberry Pi Shield, or USB stick)

## Installation

Once the SDK is available:

```bash
# Install libtropic system-wide
# (instructions TBD based on SDK release)

# Build with CGo enabled
CGO_ENABLED=1 go build ./cmd/tropicsquare-test
```

## Usage

```go
package main

import (
    "github.com/anchorageoss/visualsign-turnkeyclient/pkg/tropicsquare"
)

func main() {
    // Initialize Tropic Square device
    verifier, err := tropicsquare.NewMinimalVerifier()
    if err != nil {
        panic(err)
    }
    defer verifier.Close()

    // Verify attestation using hardware crypto
    err = verifier.VerifyAttestation(publicKey, message, signature)
    if err != nil {
        panic(err)
    }

    println("Verification successful!")
}
```

## Architecture

See [TROPIC_SQUARE_INTEGRATION_PLAN.md](../../TROPIC_SQUARE_INTEGRATION_PLAN.md) for details.

## Development

### Running Tests

```bash
# Unit tests (mock hardware)
go test ./pkg/tropicsquare

# Integration tests (requires hardware)
go test -tags=integration ./pkg/tropicsquare
```

### Building

```bash
# Standard build
go build ./pkg/tropicsquare

# TinyGo build (if targeting embedded)
tinygo build -target=riscv-qemu ./pkg/tropicsquare
```

## Resources

- [Tropic Square Website](https://tropicsquare.com/tropic01)
- [Documentation](https://github.com/tropicsquare/tropic01)
- [libtropic SDK](https://github.com/tropicsquare/libtropic) (when available)
