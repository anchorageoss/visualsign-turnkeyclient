package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TROPIC01Signer provides an interface to communicate with TROPIC01 secure element
// It abstracts the SPI/UART communication protocol
type TROPIC01Signer struct {
	port       io.ReadWriteCloser // SPI or UART device
	devicePath string
}

// DeviceInfo contains information about the TROPIC01 chip
type DeviceInfo struct {
	ChipID          string
	FirmwareVersion string
	SPECTVersion    string
}

// SignResponse contains the signature and public key from TROPIC01
type SignResponse struct {
	PublicKey []byte // 64 or 65 bytes (P-256 public key)
	Signature []byte // 64 bytes (r || s)
}

// NewTROPIC01Signer creates a new signer interface
func NewTROPIC01Signer(devicePath string) *TROPIC01Signer {
	return &TROPIC01Signer{
		devicePath: devicePath,
	}
}

// Init initializes communication with TROPIC01
func (s *TROPIC01Signer) Init() error {
	// TODO: Open SPI/UART device
	// For now, this is a placeholder
	fmt.Printf("Opening device: %s\n", s.devicePath)

	// In real implementation:
	// s.port, err = spi.Open(s.devicePath)
	// or
	// s.port, err = uart.Open(s.devicePath, 115200)

	return fmt.Errorf("not implemented: open %s and initialize TROPIC01 protocol", s.devicePath)
}

// GetDeviceInfo retrieves chip ID and firmware version from TROPIC01
func (s *TROPIC01Signer) GetDeviceInfo() (*DeviceInfo, error) {
	// Protocol message format:
	// CMD_GET_INFO (1 byte) | RESERVED (3 bytes)

	cmd := []byte{0x01, 0x00, 0x00, 0x00}

	// Send command
	if _, err := s.port.Write(cmd); err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Read response
	// Response format:
	// STATUS (1 byte) | CHIP_ID (16 bytes) | FW_VERSION (4 bytes) | SPECT_VERSION (4 bytes)
	resp := make([]byte, 25)
	if _, err := io.ReadFull(s.port, resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp[0] != 0x00 { // 0x00 = success
		return nil, fmt.Errorf("TROPIC01 returned error: 0x%02x", resp[0])
	}

	info := &DeviceInfo{
		ChipID:          fmt.Sprintf("%x", resp[1:17]),
		FirmwareVersion: fmt.Sprintf("%d.%d.%d", resp[17], resp[18], resp[19]),
		SPECTVersion:    fmt.Sprintf("%d.%d.%d", resp[21], resp[22], resp[23]),
	}

	return info, nil
}

// Sign requests TROPIC01 to sign a message hash with a specific key slot
//
// keySlot: 0-31 (ECC key slot in TROPIC01)
// hash: 32-byte message hash to sign
//
// Returns signature (r || s, 64 bytes) and the corresponding public key
func (s *TROPIC01Signer) Sign(keySlot uint8, hash []byte) (*SignResponse, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("invalid hash length: expected 32 bytes, got %d", len(hash))
	}
	if keySlot > 31 {
		return nil, fmt.Errorf("invalid key slot: %d (must be 0-31)", keySlot)
	}

	// Protocol message format:
	// CMD_SIGN (1 byte) | KEY_SLOT (1 byte) | RESERVED (2 bytes) | HASH (32 bytes)

	cmd := make([]byte, 36)
	cmd[0] = 0x02        // CMD_SIGN
	cmd[1] = keySlot     // Key slot
	copy(cmd[4:], hash)  // Hash to sign

	// Send command
	if _, err := s.port.Write(cmd); err != nil {
		return nil, fmt.Errorf("failed to send sign command: %w", err)
	}

	// Read response
	// Response format:
	// STATUS (1 byte) | RESERVED (3 bytes) | SIGNATURE (64 bytes) | PUBLIC_KEY (64 bytes)
	resp := make([]byte, 132)
	if _, err := io.ReadFull(s.port, resp); err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	if resp[0] != 0x00 {
		return nil, fmt.Errorf("signing failed with error: 0x%02x", resp[0])
	}

	return &SignResponse{
		Signature: resp[4:68],  // 64 bytes (r || s)
		PublicKey: resp[68:132], // 64 bytes (X || Y)
	}, nil
}

// GetPublicKey retrieves the public key for a given key slot
func (s *TROPIC01Signer) GetPublicKey(keySlot uint8) ([]byte, error) {
	if keySlot > 31 {
		return nil, fmt.Errorf("invalid key slot: %d (must be 0-31)", keySlot)
	}

	// Protocol message format:
	// CMD_GET_PUBKEY (1 byte) | KEY_SLOT (1 byte) | RESERVED (2 bytes)

	cmd := []byte{0x03, keySlot, 0x00, 0x00}

	// Send command
	if _, err := s.port.Write(cmd); err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Read response
	// Response format:
	// STATUS (1 byte) | RESERVED (3 bytes) | PUBLIC_KEY (64 bytes)
	resp := make([]byte, 68)
	if _, err := io.ReadFull(s.port, resp); err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	if resp[0] != 0x00 {
		return nil, fmt.Errorf("get public key failed: 0x%02x", resp[0])
	}

	return resp[4:68], nil
}

// Close closes the connection to TROPIC01
func (s *TROPIC01Signer) Close() error {
	if s.port != nil {
		return s.port.Close()
	}
	return nil
}

// Protocol command constants
const (
	CMD_GET_INFO   = 0x01
	CMD_SIGN       = 0x02
	CMD_GET_PUBKEY = 0x03
	CMD_GENERATE_KEY = 0x04
)

// Protocol status codes
const (
	STATUS_OK            = 0x00
	STATUS_INVALID_CMD   = 0x01
	STATUS_INVALID_SLOT  = 0x02
	STATUS_SIGNING_ERROR = 0x03
)

// Helper to convert uint32 to bytes (little endian)
func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
