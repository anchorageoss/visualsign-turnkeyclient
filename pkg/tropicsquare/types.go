package tropicsquare

// Device represents a connection to Tropic Square TROPIC01 secure element
type Device struct {
	// For pure Go implementation, just tracks initialization state
	// For CGo implementation, could hold libtropic handle
	initialized bool
	handle      interface{} // Optional: for future hardware handle
}

// DeviceInfo contains information about the Tropic Square device
type DeviceInfo struct {
	ChipID          string // Unique chip identifier
	FirmwareVersion string // Application firmware version
	SPECTVersion    string // SPECT (ECC engine) firmware version
	PartNumber      string // Part number (e.g., TR01-C2P-T301)
}

// VerificationData contains the data extracted from attestation for verification
type VerificationData struct {
	PublicKey    []byte `json:"publicKey"`    // 65-byte uncompressed P-256 public key
	Message      []byte `json:"message"`      // Message to verify
	Signature    []byte `json:"signature"`    // 64-byte signature (r||s)
	ManifestHash []byte `json:"manifestHash"` // SHA256 hash of QoS manifest
}
