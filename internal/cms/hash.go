package cms

import (
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

// newHashForOID returns a new [hash.Hash] for the given digest algorithm OID.
// Supported: Kupyna-256/512 (DSTU 7564), GOST 34.311-95.
// Returns nil for unsupported OIDs; callers must validate the algorithm first.
func newHashForOID(o asn1.ObjectIdentifier) hash.Hash {
	if o.Equal(oid.Kupyna256) {
		return kupyna.New256()
	}
	if o.Equal(oid.GOST34311) {
		return gost34311.New()
	}
	if o.Equal(oid.Kupyna512) {
		return kupyna.New512()
	}
	return nil
}

// isLEHashOID returns true for hash algorithms that output bytes in little-endian order
// (cryptonite convention). dstu4145.Verify / truncate expects big-endian, so callers
// must reverse the digest before passing it to Verify.
func isLEHashOID(o asn1.ObjectIdentifier) bool {
	return o.Equal(oid.GOST34311) || o.Equal(oid.Kupyna256) || o.Equal(oid.Kupyna512)
}

// unmarshalSignatureCMS accepts the national raw encoding and legacy DER signatures.
func unmarshalSignatureCMS(b []byte, curve *ec.Curve) (*dstu4145.Signature, error) {
	if len(b) == 0 || curve == nil {
		return nil, errors.New("cms: missing signature or curve")
	}
	if b[0] == 0x30 {
		if sig, err := dstu4145.UnmarshalSignature(b, curve.Words); err == nil {
			return sig, nil
		}
	}
	return dstu4145.UnmarshalSignatureRaw(b, curve)
}

// reverseBytes returns a new byte slice with bytes in reverse order.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
