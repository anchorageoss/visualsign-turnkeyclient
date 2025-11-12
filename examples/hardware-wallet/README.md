# Hardware Wallet Example: TROPIC01 + RISC-V Sidecar

This example demonstrates a hardware wallet architecture using:
- **TROPIC01 Secure Element** - For signing with private keys
- **RISC-V Sidecar Board** - For verification and attestation checking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Hardware Wallet System                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────┐         ┌───────────────────┐   │
│  │  TROPIC01 Secure     │         │  RISC-V Sidecar   │   │
│  │  Element             │◄───────►│  Verification     │   │
│  │                      │   SPI   │  Board            │   │
│  ├──────────────────────┤         ├───────────────────┤   │
│  │ • Store private keys │         │ • Verify sigs     │   │
│  │ • Sign transactions  │         │ • Check attests   │   │
│  │ • Hardware RNG       │         │ • Display/UI      │   │
│  │ • Tamper detection   │         │ • User input      │   │
│  │                      │         │                   │   │
│  │ Uses: libtropic SDK  │         │ Uses: Pure Go     │   │
│  │ Language: C          │         │ Compiled: TinyGo  │   │
│  └──────────────────────┘         └───────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Why This Architecture?

### TROPIC01 Secure Element
**Purpose:** Protect private keys, perform signing
**Advantages:**
- Private keys never leave secure element
- Tamper-proof hardware protection
- Voltage fault detection
- EM pulse detection
- Secure key storage in OTP/Flash

### RISC-V Sidecar Board
**Purpose:** Verification, UI, attestation checking
**Advantages:**
- More processing power than secure element
- Display/UI capabilities
- Network connectivity (if needed)
- Firmware updates without touching keys
- Can run complex verification logic

### Separation of Concerns
- **Signing** (secret operation) → TROPIC01 (hardware protected)
- **Verification** (public operation) → RISC-V (flexible, updatable)

## Components

### 1. TROPIC01 Signing Service (`tropic01-signer/`)
C code using libtropic SDK:
- Initialize TROPIC01 device
- Establish secure session
- Generate/manage keys in secure slots
- Sign transactions with hardware keys
- Expose simple API to RISC-V board

### 2. RISC-V Verification Service (`riscv-verifier/`)
TinyGo code for RISC-V:
- Verify ECDSA signatures (pure Go)
- Validate attestation documents
- Check transaction integrity
- Display transaction details
- User confirmation interface

### 3. Communication Protocol (`protocol.md`)
Simple SPI/UART protocol between boards:
- Request signing
- Receive signature
- Verify locally
- Display to user

## Use Case: Secure Transaction Signing

### Flow

```
1. User initiates transaction on RISC-V board
   └─> Display: "Send 1.5 ETH to 0x..."

2. RISC-V prepares transaction hash
   └─> Hash: sha256(transaction_data)

3. RISC-V sends signing request to TROPIC01
   ├─> Message: "SIGN:slot=0:hash=abc123..."
   └─> Over SPI

4. TROPIC01 performs signing
   ├─> Retrieve private key from slot 0
   ├─> Sign hash with ECDSA
   └─> Return signature (r, s)

5. RISC-V receives signature
   └─> Signature: "SIG:r=...:s=..."

6. RISC-V verifies signature locally
   ├─> Extract public key
   ├─> Verify using crypto/ecdsa (pure Go)
   └─> Check signature matches

7. RISC-V displays confirmation
   └─> "✓ Signature valid. Confirm send?"

8. User confirms → RISC-V broadcasts transaction
```

## Building

### TROPIC01 Signer (C + libtropic SDK)
```bash
cd tropic01-signer
mkdir build && cd build
cmake ..
make
```

### RISC-V Verifier (TinyGo)
```bash
cd riscv-verifier
tinygo build -target=riscv-qemu -o verifier.elf main.go
# Or for actual hardware:
tinygo build -target=<your-riscv-board> -o verifier.elf main.go
```

## Hardware Setup

### Development Setup
1. **TROPIC01 Development Board**
   - USB stick variant: https://github.com/tropicsquare/tropic01-stm32u5-usb-devkit-hw
   - Or Raspberry Pi shield: https://github.com/tropicsquare/tropic01-raspberrypi-shield-hw

2. **RISC-V Board Options**
   - SiFive HiFive1 Rev B
   - Longan Nano (GD32VF103)
   - ESP32-C3 (RISC-V core)
   - Custom RISC-V FPGA

3. **Connection**
   - SPI: MOSI, MISO, SCK, CS
   - Or UART: TX, RX
   - Ground connection

### Production Setup
- PCB with both chips
- TROPIC01 in secure position
- RISC-V with display/buttons
- Compact form factor

## Security Considerations

### What TROPIC01 Protects
✅ Private keys (never exposed)
✅ Signing operations (tamper-proof)
✅ Key generation (hardware RNG)
✅ Secure storage

### What RISC-V Verifies
✅ Signatures are valid (before broadcast)
✅ Transaction data matches display
✅ Attestations are legitimate
✅ No signature substitution

### Attack Scenarios

**Scenario 1: Compromised RISC-V Firmware**
- Attacker modifies verification code
- TROPIC01 still signs only what it's told
- Attacker can't extract private keys
- Mitigation: Attestation of RISC-V firmware

**Scenario 2: Man-in-the-Middle on SPI**
- Attacker intercepts signing requests
- Can't extract keys from TROPIC01
- Can replay signatures (needs nonce protocol)
- Mitigation: Secure session, message authentication

**Scenario 3: Physical Tampering**
- TROPIC01 detects voltage faults
- TROPIC01 detects EM pulses
- Keys erased on tamper detection
- RISC-V can be replaced/updated safely

## Example Code Structure

```
examples/hardware-wallet/
├── README.md                    # This file
├── ARCHITECTURE.md              # Detailed architecture doc
├── protocol.md                  # Communication protocol spec
│
├── tropic01-signer/             # C code for TROPIC01
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.c              # Device initialization
│   │   ├── signing.c           # Sign operations
│   │   ├── keys.c              # Key management
│   │   └── protocol.c          # SPI/UART protocol
│   ├── include/
│   │   └── wallet.h
│   └── README.md
│
├── riscv-verifier/              # TinyGo code for RISC-V
│   ├── main.go                 # Entry point
│   ├── verify.go               # Signature verification
│   ├── protocol.go             # Communication with TROPIC01
│   ├── display.go              # UI/display logic
│   └── README.md
│
├── shared/                      # Shared definitions
│   ├── protocol.h              # C header
│   └── protocol.go             # Go definitions
│
└── tests/                       # Integration tests
    ├── test_signing.sh
    ├── test_verification.sh
    └── test_protocol.sh
```

## Getting Started

### Prerequisites
- TROPIC01 development board
- RISC-V development board or QEMU
- libtropic SDK v2.0.1+
- TinyGo 0.39.0+
- CMake, GCC for ARM

### Quick Start

1. **Set up TROPIC01 signer**
   ```bash
   cd tropic01-signer
   ./build.sh
   ./flash.sh  # Flash to TROPIC01 dev board
   ```

2. **Build RISC-V verifier**
   ```bash
   cd riscv-verifier
   tinygo build -target=riscv-qemu -o verifier.elf .
   ```

3. **Test in QEMU**
   ```bash
   ./tests/test_integration.sh
   ```

4. **Deploy to hardware**
   ```bash
   # Flash both boards
   # Connect SPI/UART
   # Power on and test
   ```

## Next Steps

See individual component READMEs:
- `tropic01-signer/README.md` - libtropic SDK integration
- `riscv-verifier/README.md` - TinyGo verification code
- `protocol.md` - Communication protocol details
- `ARCHITECTURE.md` - Detailed design decisions

## References

- TROPIC01 Documentation: https://github.com/tropicsquare/tropic01
- libtropic SDK: https://github.com/tropicsquare/libtropic
- TinyGo RISC-V: https://tinygo.org/docs/reference/microcontrollers/
- Our verification package: `../../pkg/tropicsquare/`
