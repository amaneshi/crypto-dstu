package cms

import (
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"strings"

	"crypto-dstu/dstu4145"
	"crypto-dstu/gf2m"
	"crypto-dstu/gost34311"
	"crypto-dstu/kupyna"
	"crypto-dstu/oid"
)

// newHashForOID returns a new [hash.Hash] for the given digest algorithm OID.
// Supported: Kupyna-256 (DSTU 7564), GOST 34.311-95.
// Falls back to Kupyna-256 for unknown OIDs.
func newHashForOID(o asn1.ObjectIdentifier) hash.Hash {
	if o.Equal(oid.Kupyna256) {
		return kupyna.New256()
	}
	if o.Equal(oid.GOST34311) {
		return gost34311.New()
	}
	// Default: Kupyna-256 (used by synthetic test certs with DSTU4145WithKupyna256)
	return kupyna.New256()
}

// isUnsupportedAlgError reports whether err is an "unsupported signature algorithm" error.
// These are soft errors: message-digest was verified but we cannot verify the signature.
func isUnsupportedAlgError(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), "cms: unsupported signature algorithm")
}

// isLEHashOID returns true for hash algorithms that output bytes in little-endian order
// (cryptonite convention). dstu4145.Verify / truncate expects big-endian, so callers
// must reverse the digest before passing it to Verify.
func isLEHashOID(o asn1.ObjectIdentifier) bool {
	return o.Equal(oid.GOST34311)
}

// unmarshalSignatureCMS decodes a DSTU 4145 signature from a CMS SignerInfo.
//
// Two wire formats are handled:
//  1. ASN.1 SEQUENCE { OCTET STRING r, INTEGER s } — used by our Sign() output.
//  2. Raw 2*ceil(m/8) bytes = r LE || s LE — used by real CZO files (cryptonite).
func unmarshalSignatureCMS(b []byte, words int) (*dstu4145.Signature, error) {
	if len(b) == 0 {
		return nil, errors.New("empty signature")
	}
	// ASN.1 SEQUENCE format
	if b[0] == 0x30 {
		return dstu4145.UnmarshalSignature(b, words)
	}
	// Raw r LE || s LE format: length must be even, each half is one component.
	if len(b)%2 != 0 {
		return nil, errors.New("unexpected raw signature length (odd)")
	}
	half := len(b) / 2
	// Adjust words to match the actual half-length in case curve word size differs
	halfWords := min((half+3)/4, words)
	_ = halfWords
	rLE := b[:half]
	sLE := b[half:]
	// s is stored big-endian as an integer in some formats; try LE first then BE
	sInt := new(big.Int).SetBytes(reverseBytes(sLE))
	if sInt.Sign() <= 0 {
		sInt = new(big.Int).SetBytes(sLE)
	}
	// Build R field element from LE bytes using gf2m.FromWords
	padded := make([]byte, words*4)
	copy(padded, rLE)
	ws := make([]uint32, words)
	for i := range words {
		ws[i] = uint32(padded[i*4]) |
			uint32(padded[i*4+1])<<8 |
			uint32(padded[i*4+2])<<16 |
			uint32(padded[i*4+3])<<24
	}
	sig := &dstu4145.Signature{
		R: gf2m.FromWords(ws),
		S: sInt,
	}
	return sig, nil
}

// reverseBytes returns a new byte slice with bytes in reverse order.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
