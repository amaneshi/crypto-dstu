package transport

import (
	"fmt"
	gocrc32 "hash/crc32"
)

// CRC32 computes the CRC-32/IEEE checksum of data.
// This matches the polynomial used by the Ukrainian tax office protocol.
func CRC32(data []byte) uint32 {
	return gocrc32.ChecksumIEEE(data)
}

// CRC32Hex returns the CRC-32 checksum as an 8-character uppercase hex string,
// suitable for embedding in TRANSPORTABLE header fields (CRC32_SIGN, CRC32_FILE).
func CRC32Hex(data []byte) string {
	return fmt.Sprintf("%08X", CRC32(data))
}
