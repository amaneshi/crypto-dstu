// Package hmac implements HMAC (RFC 2104) with UA-specific hash constructors.
// Reference: privat-it/cryptonite src/cryptonite/c/hmac.c
package hmac

import (
	gostdhmac "crypto/hmac"
	"hash"

	"crypto-dstu/pkg/gost28147"
	"crypto-dstu/pkg/gost34311"
	"crypto-dstu/pkg/kupyna"
)

// New returns an HMAC using the given hash factory.
// This wraps [crypto/hmac.New] and accepts any [hash.Hash] factory.
func New(h func() hash.Hash, key []byte) hash.Hash {
	return gostdhmac.New(h, key)
}

// Equal performs constant-time comparison of two MACs.
// Wraps [crypto/hmac.Equal].
func Equal(mac1, mac2 []byte) bool {
	return gostdhmac.Equal(mac1, mac2)
}

// NewGOST34311 returns an HMAC keyed with GOST 34.311-95 (SboxDSTU).
// sync is the 32-byte GOST 34.311 initialization vector; nil → zero IV.
// Reference: cryptonite hmac_alloc_gost34_311.
func NewGOST34311(key, sync []byte) hash.Hash {
	s := gost28147.SboxDSTU
	iv := make([]byte, 32)
	if len(sync) > 0 {
		copy(iv, sync)
	}
	factory := func() hash.Hash {
		return gost34311.NewWithParams(s, iv)
	}
	return gostdhmac.New(factory, key)
}

// NewKupyna256 returns HMAC-Kupyna-256.
// Reference: cryptonite hmac_alloc_kupyna (variant 256).
func NewKupyna256(key []byte) hash.Hash {
	return gostdhmac.New(kupyna.New256, key)
}

// NewKupyna512 returns HMAC-Kupyna-512.
// Reference: cryptonite hmac_alloc_kupyna (variant 512).
func NewKupyna512(key []byte) hash.Hash {
	return gostdhmac.New(kupyna.New512, key)
}
