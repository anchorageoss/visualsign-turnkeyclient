# TinyGo Binary Size Optimization

## Test Results

| Binary | Size | Configuration |
|--------|------|---------------|
| verify-full-test.elf (original) | 3.1M | Default (with debug) |
| verify-nodebug.elf | **1.5M** | With `-no-debug` |
| verify-upx.elf | ❌ Failed | UPX not supported for RISC-V |

**Best result: 52% size reduction with `-no-debug` flag alone**

## Optimization Methods

### 1. TinyGo `-no-debug` Flag (Recommended)

**Most effective and easiest:**

```bash
tinygo build -target=riscv-qemu -no-debug -o output.elf main.go
```

**Removes:**
- Debug symbols (DWARF)
- Line number information
- Source file references
- Function names (partial)

**Actual reduction:** 52% (3.1M → 1.5M) ✅ **TESTED AND WORKING**

**Pros:**
- Built-in TinyGo feature
- No external tools needed
- Still produces working binary
- **Only method that works for RISC-V bare-metal**

**Cons:**
- Harder to debug if something goes wrong
- No stack traces with function names

### 2. Optimization Level (Already Default)

TinyGo uses `-opt=z` (optimize for size) by default.

Other options:
```bash
-opt=0  # No optimization (larger, easier to debug)
-opt=1  # Basic optimization
-opt=2  # Full optimization (speed)
-opt=s  # Optimize for size (similar to z)
-opt=z  # Optimize for size (DEFAULT - most aggressive)
```

**Note:** You're already getting this! No action needed.

### 3. System `strip` Command ❌ **DOES NOT WORK**

**DO NOT USE for TinyGo RISC-V binaries:**

```bash
strip output.elf
# Error: Unable to recognise the format of the input file
```

**Why it fails:**
- TinyGo produces bare-metal RISC-V binaries
- System `strip` expects Linux ELF format (with OS headers)
- RISC-V bare-metal has different ELF structure
- `strip` doesn't recognize the format

**Tested and confirmed:** ❌ `strip` command fails on TinyGo RISC-V binaries

### 4. UPX Compression ❌ **DOES NOT WORK**

**UPX does not support RISC-V architecture:**

```bash
upx --best output.elf
# Error: UnknownExecutableFormatException
```

**Why it fails:**
- UPX supports: x86, ARM, MIPS, PowerPC, etc.
- UPX does NOT support: RISC-V (any variant)
- No decompression stub available for RISC-V

**Tested and confirmed:** ❌ UPX fails on RISC-V binaries

**Alternative:** Some embedded systems use custom compression:
- gzip the binary, decompress at boot
- Custom bootloader with decompression
- Trade-off: Slower boot, more complex bootloader

### 5. Reduce Dependencies

**Manual code optimization:**

Remove unused imports:
```go
// Before
import (
    "encoding/json"  // Not used
    "fmt"
    "crypto/sha256"
)

// After
import (
    "fmt"
    "crypto/sha256"
)
```

TinyGo's dead code elimination is good, but explicit removal helps.

### 6. Build Tags (Advanced)

Conditionally exclude code:

```go
// +build !minimal

package features

func ExpensiveFeature() {
    // Only included in full builds
}
```

Build without it:
```bash
tinygo build -tags=minimal -target=riscv-qemu -o minimal.elf
```

## Recommended Build Commands

### Development Build (with debugging)
```bash
tinygo build -target=riscv-qemu -o debug.elf main.go
# Size: ~3-5MB
# Has: Full debug symbols
```

### Production Build (optimized)
```bash
tinygo build -target=riscv-qemu -no-debug -o release.elf main.go
# Size: ~1.5-2MB
# Has: No debug symbols
```

### Ultra-Compact Build (constrained devices)
```bash
# Only -no-debug works for RISC-V
tinygo build -target=riscv-qemu -no-debug -o compact.elf main.go
# Final size: 1.5M

# Note: UPX and strip do NOT work on RISC-V bare-metal binaries
```

## Size Comparison (Tested)

| Build Type | Size | Status | Use Case |
|------------|------|--------|----------|
| Default (with debug) | 3.1M | ✅ Works | Development, debugging |
| -no-debug | 1.5M | ✅ **BEST OPTION** | Production |
| -no-debug + strip | ❌ Failed | N/A | strip doesn't work on RISC-V bare-metal |
| -no-debug + UPX | ❌ Failed | N/A | UPX doesn't support RISC-V |

**Achievable reduction: 52% (3.1M → 1.5M) using `-no-debug` only**

## Memory Usage

Size optimization affects **flash/storage**, not RAM:

| Resource | Usage | Notes |
|----------|-------|-------|
| Flash | 1.5-3MB | Where binary is stored |
| RAM (runtime) | ~100-200KB | Heap + stack during execution |
| Stack per goroutine | 2-8KB | Configurable with -stack-size |

## Target-Specific Considerations

### For Embedded Devices (SiFive, Longan Nano)

```bash
# Check target requirements
tinygo info hifive1b

# Build for specific target
tinygo build -target=hifive1b -no-debug -o firmware.elf
```

### For QEMU Testing

```bash
# QEMU doesn't care about size, use debug build
tinygo build -target=riscv-qemu -o test.elf
```

## Verification Example Sizes

### Minimal Verification Only (tropicsquare package)

```bash
# Just signature verification
tinygo build -target=riscv-qemu -no-debug \
  -o verify-minimal.elf \
  examples/hardware-wallet/riscv-verifier/

# Expected: ~800KB (crypto/ecdsa + protocol)
```

### Full Verification Stack

```bash
# With attestation parsing, CBOR, Borsh
tinygo build -target=riscv-qemu -no-debug \
  -o verify-full.elf \
  cmd/tinygo-verify-full/

# Expected: ~1.5-2MB
```

## Troubleshooting

### Binary too large for flash

1. Use `-no-debug` (gives 52% reduction)
2. Remove unused features/imports
3. Check if target has external flash
4. Consider custom compression in bootloader (advanced)

### Binary won't run after stripping

- ❌ System `strip` doesn't work on RISC-V bare-metal (format not recognized)
- ❌ UPX doesn't work on RISC-V (architecture not supported)
- ✅ Only use TinyGo's `-no-debug` flag (tested and working)

### Out of memory at runtime

- Reduce stack size: `-stack-size=2KB`
- Use smaller data structures
- Avoid large global arrays
- Stream data instead of buffering

## Measuring Actual Usage

```bash
# Size breakdown
tinygo build -target=riscv-qemu -size=full -o output.elf

# Shows:
# - Code size by package
# - Data segment sizes
# - Total flash usage
```

## Conclusion

**For production hardware wallet:**

```bash
tinygo build \
  -target=<your-board> \
  -no-debug \
  -o wallet.elf \
  examples/hardware-wallet/riscv-verifier/
```

**Final size: ~1.5M** (tested with full verification stack)

**Summary of what works:**
- ✅ `-no-debug` flag: 52% reduction (3.1M → 1.5M)
- ❌ `strip` command: Doesn't recognize RISC-V bare-metal format
- ❌ UPX compression: RISC-V not supported

**Hardware requirements:** 2-4MB flash minimum (1.5M binary + data)
