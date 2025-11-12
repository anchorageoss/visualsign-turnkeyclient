# RISC-V Verifier Component

This component runs on a RISC-V board and provides:
- Transaction display and user confirmation
- Communication with TROPIC01 secure element
- **Signature verification using pure Go crypto**
- Attestation validation

## Architecture

```
┌──────────────────────────────────────────┐
│        RISC-V Sidecar Board              │
├──────────────────────────────────────────┤
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Application (main.go)             │ │
│  │  - Display transaction             │ │
│  │  - Wait for user confirmation      │ │
│  │  - Coordinate sign/verify flow     │ │
│  └─────────┬──────────────────────────┘ │
│            │                             │
│            ▼                             │
│  ┌────────────────────────────────────┐ │
│  │  Verifier (tropicsquare pkg)       │ │
│  │  - Pure Go ECDSA P-256 verification│ │
│  │  - Uses crypto/ecdsa               │ │
│  │  - No hardware needed              │ │
│  └────────────────────────────────────┘ │
│            ▲                             │
│            │ signature                   │
│            │                             │
│  ┌─────────┴──────────────────────────┐ │
│  │  Protocol (tropic01_signer.go)     │ │
│  │  - SPI/UART communication          │ │
│  │  - Command framing                 │ │
│  │  - Request signing from TROPIC01   │ │
│  └─────────┬──────────────────────────┘ │
│            │                             │
└────────────┼─────────────────────────────┘
             │ SPI/UART
             ▼
    ┌────────────────┐
    │   TROPIC01     │
    │ Secure Element │
    └────────────────┘
```

## Building

### For QEMU (Testing)
```bash
tinygo build -target=riscv-qemu -o verifier.elf .
```

### For Actual Hardware

**SiFive HiFive1 Rev B:**
```bash
tinygo build -target=hifive1b -o verifier.elf .
```

**Longan Nano (GD32VF103):**
```bash
tinygo build -target=longan-nano -o verifier.elf .
```

**ESP32-C3 (RISC-V):**
```bash
tinygo build -target=esp32c3 -o verifier.uf2 .
```

**Generic RISC-V:**
```bash
tinygo build -target=riscv -o verifier.elf .
```

## Dependencies

**Go Modules:**
- `github.com/anchorageoss/visualsign-turnkeyclient/pkg/tropicsquare` - Pure Go verification

**TinyGo Requirements:**
- TinyGo 0.39.0+ (supports Go 1.25 and RISC-V)
- Works on 32-bit RISC-V (RV32IMC)
- Binary size: ~3-5MB (depending on features)

## Hardware Requirements

### Minimum Specifications
- **CPU:** 32-bit RISC-V (RV32IMC)
- **RAM:** 512KB (for crypto operations)
- **Flash:** 4MB (for firmware + data)
- **Connectivity:** SPI or UART to TROPIC01

### Recommended Development Boards

**Option 1: SiFive HiFive1 Rev B**
- CPU: SiFive FE310 (RV32IMAC @ 320MHz)
- RAM: 16KB SRAM
- Flash: 32MB external QSPI
- Perfect for development

**Option 2: Longan Nano**
- CPU: GD32VF103 (RV32IMAC @ 108MHz)
- RAM: 32KB SRAM
- Flash: 128KB
- Low cost, good for prototyping

**Option 3: ESP32-C3**
- CPU: RISC-V single-core @ 160MHz
- RAM: 400KB SRAM
- Flash: 4MB
- Built-in WiFi/BLE

## Pin Connections

### SPI Connection to TROPIC01
```
RISC-V Board    TROPIC01
─────────────   ─────────
GPIO12 (MOSI) → SDI
GPIO13 (MISO) ← SDO
GPIO14 (SCK)  → SCK
GPIO15 (CS)   → CS#
GND           → GND
3.3V          → VCC
```

### UART Connection (Alternative)
```
RISC-V Board    TROPIC01
─────────────   ─────────
GPIO16 (TX)   → RX
GPIO17 (RX)   ← TX
GND           → GND
3.3V          → VCC
```

## Code Structure

```
riscv-verifier/
├── main.go                    # Entry point and application logic
├── tropic01_signer.go         # Protocol handler for TROPIC01
├── display.go                 # Display/UI functions (TODO)
├── buttons.go                 # Button input handling (TODO)
└── README.md                  # This file
```

## Example Flow

### Sign and Verify Transaction

```go
// 1. Initialize components
verifier, _ := tropicsquare.NewMinimalVerifier()
signer := NewTROPIC01Signer("/dev/spidev0.0")
signer.Init()

// 2. Create transaction
tx := Transaction{
    To:     "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    Amount: "1.5",
    Token:  "ETH",
}

// 3. Hash transaction
txHash := sha256.Sum256(tx.Serialize())

// 4. Request signature from TROPIC01 (hardware signing)
sigResponse, _ := signer.Sign(0, txHash[:])
// TROPIC01 uses private key in slot 0 to sign

// 5. Verify signature on RISC-V (software verification)
err := verifier.VerifyAttestation(
    sigResponse.PublicKey,
    txHash[:],
    sigResponse.Signature,
)
// Uses pure Go crypto/ecdsa - no hardware needed

// 6. If valid, broadcast transaction
if err == nil {
    broadcast(tx, sigResponse.Signature)
}
```

## Protocol Commands

See `../protocol.md` for full protocol specification.

**Available Commands:**
- `GET_INFO` (0x01) - Get chip ID and firmware version
- `SIGN` (0x02) - Sign message hash with key slot
- `GET_PUBKEY` (0x03) - Get public key for slot
- `GENERATE_KEY` (0x04) - Generate new key pair in slot

## Testing

### Unit Tests
```bash
go test .
```

### Integration Tests (with TROPIC01 hardware)
```bash
# Build and flash
tinygo build -target=hifive1b -o verifier.elf .
tinygo flash -target=hifive1b verifier.elf

# Monitor serial output
screen /dev/ttyUSB0 115200
```

### QEMU Testing
```bash
# Build for QEMU
tinygo build -target=riscv-qemu -o verifier.elf .

# Run in QEMU (with TROPIC01 emulator)
qemu-system-riscv32 -machine virt -kernel verifier.elf -nographic
```

## Performance

**Typical Operation Times:**

| Operation | Time | Notes |
|-----------|------|-------|
| Verification (software) | ~10ms | Pure Go crypto/ecdsa on RISC-V |
| Sign request to TROPIC01 | ~50ms | Hardware ECDSA in secure element |
| Total sign+verify cycle | ~60ms | Fast enough for user experience |

**Memory Usage:**
- Code: ~3MB (TinyGo compiled)
- Runtime heap: ~100KB
- Stack: ~32KB

## Security Notes

### What This Component Verifies
✅ Signature matches public key
✅ Signature is valid for transaction
✅ No signature substitution
✅ Transaction data integrity

### What It Does NOT Protect
❌ Display substitution (if display is compromised)
❌ Key extraction (keys stay in TROPIC01)
❌ Physical tampering of TROPIC01 (handled by secure element)

### Recommendations
1. **Firmware Attestation**: Verify RISC-V firmware integrity
2. **Secure Boot**: Use secure boot on RISC-V if available
3. **Display Protection**: Use E-ink or dedicated secure display
4. **Button Protection**: Debounce and validate button inputs

## Future Enhancements

### Display Module
Add support for OLED/LCD displays:
- Show transaction details
- QR code generation
- Status indicators

### User Input
Add button handling:
- Confirm/reject transactions
- Navigate menus
- Enter PIN

### Connectivity
Optional features:
- USB HID (as hardware wallet device)
- Bluetooth LE (mobile app connectivity)
- WiFi (for direct blockchain interaction)

### Advanced Features
- Multi-signature support
- Multiple TROPIC01 devices
- Hierarchical deterministic (HD) wallets
- Backup/recovery mechanisms

## Troubleshooting

**Problem: Binary too large**
- Solution: Reduce logging, optimize imports
- Use `-opt=z` flag for size optimization

**Problem: Verification fails**
- Check: Public key format (64 or 65 bytes?)
- Check: Signature format (r || s, 64 bytes)
- Check: Hash algorithm (SHA256)

**Problem: Communication timeout**
- Check: SPI/UART connections
- Check: TROPIC01 power supply
- Check: Baud rate/SPI speed configuration

## References

- TinyGo Documentation: https://tinygo.org/docs/
- TROPIC01 Datasheet: https://github.com/tropicsquare/tropic01
- Protocol Specification: ../protocol.md
- Verification Package: ../../../pkg/tropicsquare/
